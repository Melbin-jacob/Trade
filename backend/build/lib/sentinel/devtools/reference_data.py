"""Fictitious reference data for tests and the offline demo.

The sanctions entries below are INVENTED for testing and are not real listed
parties. Production loads the official lists (see regulatory.sanctions.download_ofac).
"""

DEMO_SDN_CSV = """\
90001,"NORTHERN STAR MARITIME HOLDINGS FZE","-0- ","DEMO-PROGRAM","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","Fictitious test entry"
90002,"KESTREL BULK SHIPPING CO., LTD.","-0- ","DEMO-PROGRAM","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","Fictitious test entry"
90003,"VOLKOV, Arkady Petrovich","individual","DEMO-PROGRAM","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","Fictitious test entry"
"""

DEMO_ALT_CSV = """\
90001,1,"aka","NORDSTAR MARITIME FZE","-0- "
90002,2,"aka","KESTREL BULK LINES","-0- "
"""

DEMO_TARIFF_CSV = """\
country,hs_code,description,mfn_rate
CA,090111,"Coffee, not roasted, not decaffeinated",Free
CA,090121,"Coffee, roasted, not decaffeinated",Free
CA,080390,"Bananas, fresh",Free
CA,0804,"Dates, figs, pineapples, avocados, guavas, mangoes",Free
US,090111,"Coffee, not roasted, not decaffeinated",Free
"""
