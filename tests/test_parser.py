from analyzer.email_parser import parse_email, extract_body


with open("samples/test_email.eml", "rb") as file:
    email_bytes = file.read()


result = parse_email(email_bytes)

print("\n===== EMAIL HEADERS =====\n")

for key, value in result["headers"].items():
    print(f"{key}: {value}")


text_body, html_body = extract_body(result["message"])

print("\n===== TEXT BODY =====\n")
print(text_body)

print("\n===== HTML BODY =====\n")
print(html_body)