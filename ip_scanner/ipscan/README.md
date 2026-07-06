# IP Scanner

Basit Flask tabanlı IP çözümleme + port tarama paneli.

## Kurulum
```
pip install -r requirements.txt
python app.py
```

Tarayıcıda: http://localhost:5000

## Özellikler
- Domain -> IP çözümleme + reverse DNS
- Çoklu thread port tarama (aralık veya liste: `1-1024`, `80,443,22`)
- Servis tahmini + banner grabbing
- Canlı ilerleme çubuğu (polling)

## Notlar
- Tek seferde en fazla 5000 port taranabilir (kötüye kullanım koruması).
- Bu araç yalnızca sahibi olduğun veya izinli sistemlerde kullanılmalıdır.
