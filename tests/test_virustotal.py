from analyzer.virustotal import check_url_reputation


test_url = "https://example.com"


print("\n===== VIRUSTOTAL URL CHECK =====\n")

result = check_url_reputation(test_url)

for key, value in result.items():
    print(f"{key}: {value}")