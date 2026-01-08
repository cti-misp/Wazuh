# Export MISP to Wazuh

สคริปต์สำหรับดึง IOC (Indicators of Compromise) จาก MISP เพื่อนำไปใช้งานกับ Wazuh (CDB List)

## สิ่งที่ต้องเตรียม (Prerequisites)

1.  Python 3.x
2.  สร้างและเปิดใช้งาน Virtual Environment:
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  ติดตั้ง library ที่จำเป็น:
    ```bash
    pip install -r requirements.txt
    ```

## การตั้งค่า (Configuration)

เปิดไฟล์ `export_misp_to_wazuh.py` และแก้ไขค่าดังต่อไปนี้ให้ตรงกับ MISP ของคุณ:

```python
MISP_URL = "https://{IP-MISP}/" # ใส่ URL ของ MISP Server
API_KEY = "{API-Key}"           # ใส่ API Key ของคุณ
VERIFY_SSL = False              # เปลี่ยนเป็น True หากต้องการตรวจสอบ SSL
```

## วิธีการใช้งาน (Usage)

### 1. แบบดึงข้อมูลทั้งหมด (Batch Export)
คำสั่งนี้จะทำการดึงข้อมูล IOC 4 ประเภทหลักแยกเป็น 4 ไฟล์ให้อัตโนมัติ ได้แก่:
- `misp_ip-src` (สำหรับ ip-src)
- `misp_ip-dst` (สำหรับ ip-dst)
- `misp_sha256` (สำหรับ sha256)
- `misp_domain` (สำหรับ domain)

```bash
python3 export_misp_to_wazuh.py all
```

### 2. แบบเลือกดึงเฉพาะไฟล์ (Single Export)
หากต้องการดึงเฉพาะบางประเภท หรือกำหนดชื่อไฟล์เอง:

```bash
# รูปแบบ: python3 export_misp_to_wazuh.py [ชื่อไฟล์] --type [ประเภทAttribute]

# ตัวอย่าง: ดึง SHA256
python3 export_misp_to_wazuh.py misp_sha256 --type sha256

# ตัวอย่าง: ดึง IP Source
python3 export_misp_to_wazuh.py my_ips.txt --type ip-src
```

### 3. กำหนดโฟลเดอร์ปลายทาง (Output Directory)
สามารถใช้ option `--output-dir` เพื่อระบุโฟลเดอร์ที่ต้องการบันทึกไฟล์ (หากไม่มีโฟลเดอร์สคริปต์จะสร้างให้)

```bash
# ตัวอย่าง: ดึงข้อมูลทั้งหมดลงโฟลเดอร์ ./output
python3 export_misp_to_wazuh.py all --output-dir ./output

# ตัวอย่าง: ดึงเฉพาะไฟล์ SHA256 ลงโฟลเดอร์ /tmp/ioc
python3 export_misp_to_wazuh.py misp_sha256 --type sha256 --output-dir /tmp/ioc
```

## รูปแบบข้อมูล (Output Format)
ไฟล์ที่ได้จะเป็นรูปแบบ Wazuh CDB:
```text
value:Event_event_id
```
ตัวอย่าง:
```text
1.2.3.4:Event_1234
malicious.com:Event_5678
```
