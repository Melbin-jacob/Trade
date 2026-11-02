"""Hybrid extraction pipeline: OCR text -> schema-bound LLM -> grounded scoring."""

from __future__ import annotations

import json

from sentinel.agents.claude import UNTRUSTED_DATA_RULES, JsonLlm
from sentinel.core.canonical import canonical_json
from sentinel.domain.documents import (
    BillOfLading,
    CertificateOfOrigin,
    CommercialInvoice,
    DocumentType,
    PackingList,
    PhytosanitaryCertificate,
)
from sentinel.extraction.grounding import Calibration, Scorer
from sentinel.extraction.llm_view import assemble, model_schema
from sentinel.extraction.ocr import OcrEngine
from sentinel.ingestion.inspection import sniff_media_type
from sentinel.kernel.service import ShipmentService
from sentinel.kernel.shipment import ShipmentAggregate
from sentinel.security.principals import Principal
from sentinel.storage.blobs import EncryptedBlobStore

MODELS = {
    DocumentType.COMMERCIAL_INVOICE: CommercialInvoice,
    DocumentType.PACKING_LIST: PackingList,
    DocumentType.BILL_OF_LADING: BillOfLading,
    DocumentType.CERTIFICATE_OF_ORIGIN: CertificateOfOrigin,
    DocumentType.PHYTOSANITARY_CERTIFICATE: PhytosanitaryCertificate,
}

PIPELINE_VERSION = "extract-1.0"

SYSTEM_PROMPT = f"""You extract data from international trade documents (commercial invoices, \
bills of lading, packing lists, certificates of origin, phytosanitary certificates) into a fixed JSON schema.

How to fill each field:
- "value": the value exactly as the document states it. Normalise only the format: numbers as plain \
decimals without thousands separators (24,480.50 -> 24480.50), dates as YYYY-MM-DD, countries as ISO 3166-1 \
alpha-2 codes, currencies as ISO 4217 codes, weight units as KG, LB or MT, HS codes as digits only.
- "evidence": copy the exact characters from the document that show the value, e.g. "Gross Weight: 24,480.50 KG". \
Copy, do not paraphrase. A downstream checker verifies every quote against the document text, and values \
whose quotes cannot be found are sent to a human.
- If a value is not on the document, set value to null and evidence to "". Do not infer, compute or guess \
missing values - a human reviewer will fill gaps, and a guessed value is worse than a missing one.
- For line items, produce one entry per printed line, in order, numbering line_no from 1.

{UNTRUSTED_DATA_RULES}"""


def document_key(shipment_id: str, content_sha256: str) -> str:
    return f"extractions/{shipment_id.lower()}/{content_sha256}.json"


class ExtractionPipeline:
    def __init__(self, *, principal: Principal, service: ShipmentService, blobs: EncryptedBlobStore,
                 ocr: OcrEngine, llm: JsonLlm, calibration: Calibration | None = None) -> None:
        self._principal = principal
        self._service = service
        self._blobs = blobs
        self._ocr = ocr
        self._llm = llm
        self._calibration = calibration or Calibration()

    def extract(self, tenant_id: str, doc_type: DocumentType, content: bytes):
        media_type = sniff_media_type(content) or "application/octet-stream"
        ocr = self._ocr.read(content, media_type)
        model = MODELS[doc_type]
        data = self._llm.complete_json(
            purpose=f"extract:{doc_type.value}",
            system=SYSTEM_PROMPT,
            user=f"Document type: {doc_type.value}\n<document>\n{ocr.text}\n</document>",
            schema=model_schema(model),
            tenant_id=tenant_id,
            actor=self._principal.audit_ref(),
        )
        return assemble(model, data, Scorer(ocr, self._calibration)), ocr.engine

    def process(self, agg: ShipmentAggregate, content_sha256: str) -> ShipmentAggregate:
        version = next(
            (v[-1] for v in agg.documents.values() if v and v[-1].content_sha256 == content_sha256), None
        )
        if version is None:
            raise LookupError("not the current version of any document")
        storage_key = version.storage_uri.removeprefix(f"blob://{agg.tenant_id}/")
        content = self._blobs.get(agg.tenant_id, storage_key)
        document, engine = self.extract(agg.tenant_id, version.doc_type, content)
        self._blobs.put(agg.tenant_id, document_key(agg.shipment_id, content_sha256),
                        canonical_json({"doc_type": version.doc_type, "ocr_engine": engine,
                                        "document": document}))
        return self._service.record_extraction(
            self._principal, agg.tenant_id, agg.shipment_id, content_sha256, document,
            f"{PIPELINE_VERSION}+{engine}",
        )



def load_document(blobs: EncryptedBlobStore, tenant_id: str, shipment_id: str, content_sha256: str):
    raw = json.loads(blobs.get(tenant_id, document_key(shipment_id, content_sha256)))
    doc_type = DocumentType(raw["doc_type"])
    return MODELS[doc_type].model_validate(raw["document"])
