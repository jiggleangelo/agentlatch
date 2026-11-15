POLICY = {"version":1,"rules":[
 {"agent":"invoice-bot","tool":"crm.lookup_account","effect":"allow","constraints":{"account_id":{"max_len":64}}},
 {"agent":"invoice-bot","tool":"payments.refund","effect":"allow","constraints":{"amount":{"min":0.01,"max":100},"currency":{"in":["EUR"]},"order_id":{"max_len":64}},"rate_per_minute":5},
 {"agent":"support-triage","tool":"crm.lookup_account","effect":"allow","constraints":{"account_id":{"max_len":64}}},
 {"agent":"support-triage","tool":"files.read","effect":"allow","constraints":{"path":{"prefix":"/srv/reports/","max_len":256}}},
 {"agent":"research-scraper","tool":"files.read","effect":"allow","constraints":{"path":{"prefix":"/srv/reports/public/","max_len":256}}},
 {"agent":"*","tool":"email.send","effect":"deny"}]}
AGENTS = ("invoice-bot", "support-triage", "research-scraper")
