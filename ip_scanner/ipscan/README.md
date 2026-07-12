# IP Scanner v0.1.1

Basit Flask tabanlı IP çözümleme + port tarama paneli.

## Kurulum
```
pip install -r requirements.txt
python app.py
```

Tarayıcıda: http://localhost:5000

## Özellikler
- **Gelişmiş URL/domain → IP çözümleme**: tam URL (`https://site.com/yol?x=1`), `domain.com:port` veya düz IP kabul eder; tüm A (IPv4) ve AAAA (IPv6) kayıtlarını, CNAME zincirini, MX/NS/TXT kayıtlarını ve her IP için reverse DNS'i tek seferde gösterir (dnspython ile, kurulu değilse temel sockete düşer)
- Çoklu thread port tarama (aralık veya liste: `1-1024`, `80,443,22`)
- Servis tahmini + banner grabbing
- Canlı ilerleme çubuğu (polling)
- Host canlı kontrolü (ping) + gecikme ölçümü
- Taramayı iptal etme
- Tarama geçmişi (son 25 tarama)
- Sonuçları JSON/CSV olarak dışa aktarma
- SSL/TLS sertifika bilgisi (443, 8443 vb. portlarda)
- CIDR / alt ağ tarama (örn. `192.168.1.0/24`) — subnet içindeki canlı hostları ve açık portlarını bulur
- WHOIS sorgulama (domain veya IP, tam URL de girilebilir)
- Traceroute (hedefe giden yol/hop listesi)
- GeoIP bilgisi (ülke, şehir, ISP, AS numarası)
- Port ön ayarları (Web, Veritabanı, Uzak Erişim, Mail, Oyun, İlk 1024)

## Notlar
- Tek seferde en fazla 5000 port taranabilir (kötüye kullanım koruması).
- Alt ağ taramasında en fazla /24 (256 host) ve host başına 50 port desteklenir.
- Traceroute için sisteminizde `traceroute` (Linux/Mac) veya `tracert` (Windows) kurulu olmalı.
- GeoIP bilgisi ücretsiz ip-api.com servisinden alınır, internet bağlantısı gerektirir.
- Gelişmiş DNS çözümleme için `dnspython` kurulu olmalı (requirements.txt içinde); kurulu değilse araç yalnızca A kaydına (tek/çoklu IPv4) düşer.
- Bu araç yalnızca sahibi olduğun veya izinli sistemlerde kullanılmalıdır.
