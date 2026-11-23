"""正式報告與既有陣列格式的共同讀取規則。"""


def finding_items(document):
    items = document.get("findings") if isinstance(document, dict) else document
    if not isinstance(items, list):
        raise ValueError("reports/findings.json 應為陣列，或含 findings 陣列的物件")
    return items
