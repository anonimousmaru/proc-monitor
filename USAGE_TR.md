# Proc-Monitor Kullanım Kılavuzu

## Genel Bakış

Proc-Monitor, yüksek CPU/RAM tüketen prosesleri tespit eden ve bunların hangi servis veya programlar tarafından oluşturulduğunu bulan hafif bir Linux izleme aracıdır. **Harici bağımlılık gerektirmez** - sadece Python 3.6+ yeterlidir.

## Hızlı Başlangıç

### Tek Satırda İndir ve Çalıştır
```bash
curl -sL https://raw.githubusercontent.com/cagatayuresin/proc-monitor/main/proc_monitor.py | sudo python3 -
```

### İndir ve Çalıştır
```bash
# İndir
wget https://raw.githubusercontent.com/cagatayuresin/proc-monitor/main/proc_monitor.py

# Çalıştır
sudo python3 proc_monitor.py
```

### Repoyu Klonla
```bash
git clone https://github.com/cagatayuresin/proc-monitor.git
cd proc-monitor
sudo python3 proc_monitor.py
```

## Yapılandırma

`proc_monitor.py` ile aynı dizinde `config.json` dosyası oluşturun:

```json
{
    "mode": "threshold",
    "top_n": 5,
    "cpu_threshold": 50.0,
    "ram_threshold": 10.0,
    "check_interval": 0.3,
    "output_file": "resource_report.json",
    "track_cpu": true,
    "track_ram": true
}
```

### Yapılandırma Seçenekleri

| Seçenek | Tip | Varsayılan | Açıklama |
|---------|-----|------------|----------|
| `mode` | string | "threshold" | Tespit modu: `"threshold"` veya `"top_n"` |
| `top_n` | int | 5 | İzlenecek en yüksek proses sayısı (sadece `top_n` modunda) |
| `cpu_threshold` | float | 50.0 | Tespit için CPU kullanım yüzdesi eşiği (sadece `threshold` modunda) |
| `ram_threshold` | float | 10.0 | Tespit için RAM kullanım yüzdesi eşiği (sadece `threshold` modunda) |
| `check_interval` | float | 0.3 | Kontroller arası saniye (düşük = daha fazla kısa ömürlü proses yakalar) |
| `output_file` | string | "resource_report.json" | Rapor dosyasının yolu |
| `track_cpu` | bool | true | CPU izlemeyi etkinleştir |
| `track_ram` | bool | true | RAM izlemeyi etkinleştir |

### Modlar

**Threshold (Eşik) Modu** (`"mode": "threshold"`):
- CPU veya RAM eşiklerini aşan TÜM prosesleri yakalar
- Bir limiti aşan herhangi bir prosesi yakalamak için idealdir

**Top-N Modu** (`"mode": "top_n"`):
- CPU ve RAM kullanımına göre en yüksek N prosesi yakalar
- En yüksek kaynak tüketen proseslerin sürekli izlenmesi için idealdir

`config.json` yoksa varsayılan değerler kullanılır.

## Çalıştırma

### Temel Kullanım
```bash
sudo python3 proc_monitor.py
```

> **Not:** Tüm proses bilgilerine erişim için root yetkileri önerilir.

### İzlemeyi Durdur
İzlemeyi durdurmak ve rapor oluşturmak için `CTRL+C` tuşlarına basın.

## Çıktıyı Anlama

### Gerçek Zamanlı Konsol Çıktısı
```
[2024-01-15 10:30:45] [CPU] stress (PID:12345)
    CPU: 98.5% | RAM: 0.3% (12.4 MB)
    Service: stress-test.service
    User: root
    Chain: stress(12345) -> bash(12300) -> systemd(1)
    Cmd: /usr/bin/stress --cpu 1
```

- **Zaman Damgası**: Prosesin tespit edildiği an
- **Tetikleyici**: Tespiti neyin tetiklediği (CPU, RAM veya her ikisi)
- **Servis**: Prosese sahip systemd servisi veya scope
- **Zincir**: Üst proses zinciri (proses -> ebeveyn -> büyük ebeveyn)
- **Cmd**: Prosesi başlatan komut satırı

### Rapor Dosyası (JSON)

Rapor şunları içerir:
- **config**: İzleme sırasında kullanılan yapılandırma
- **summary**: Servise göre toplu veri
- **events**: Tüm bireysel tespit olayları

Örnek özet bölümü:
```json
{
  "summary": {
    "total_events": 150,
    "by_service": {
      "apache2.service": {
        "count": 100,
        "processes": [...]
      }
    }
  }
}
```

## Kullanım Senaryoları

### Kısa Ömürlü CPU Yiyicileri Bulma
```json
{
    "cpu_threshold": 30.0,
    "check_interval": 0.1,
    "track_ram": false
}
```

### Bellek Sızıntısı Tespiti
```json
{
    "ram_threshold": 5.0,
    "check_interval": 1.0,
    "track_cpu": false
}
```

### Kapsamlı İzleme
```json
{
    "cpu_threshold": 40.0,
    "ram_threshold": 8.0,
    "check_interval": 0.5
}
```

## Sorun Giderme

### "Permission Denied" Hataları
Tam erişim için `sudo` ile çalıştırın:
```bash
sudo python3 proc_monitor.py
```

### "/proc filesystem not found"
Bu araç sadece `/proc` dosya sistemi olan Linux sistemlerde çalışır.

### Prosesler Çok Hızlı Kayboluyor
Yapılandırmada `check_interval` değerini düşürün:
```json
{
    "check_interval": 0.1
}
```

## Nasıl Çalışır

1. `/proc` dosya sistemini doğrudan okur (harici kütüphane yok)
2. Aralıklar arası proses tik'lerini karşılaştırarak CPU kullanımını hesaplar
3. Bellek bilgisini `/proc/<pid>/statm`'den alır
4. `/proc/<pid>/cgroup`'dan üst servisleri bulur
5. PPID'leri takip ederek ebeveyn zinciri oluşturur

## Gereksinimler

- **İşletim Sistemi**: Linux (Ubuntu, Debian, CentOS, vb.)
- **Python**: 3.6 veya üzeri
- **Yetkiler**: Root önerilir (olmadan da çalışabilir ama sınırlı erişim)
