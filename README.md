# MMSEC SoSe2025

## Inhalt
- Browseranalysen
    - Netwerkmitschnitte
    - AmIUnique Json Dateien
- Scripts
    - Blocker Script das Browser Starter (Browser muss im Script angepasst werden) und iptables anspricht um unerwünschte Kommunikation zu blocken
        - Regeln werden bei Keyboard Interrupt (strg+c, control+c) auch im OpenSnitch Format exportiert
    - Python Installer um python auf Debian zu installieren und kompilieren
        - Setzt außerdem Symlink um die installierte Version mit "python" aufzurufen
        - Standardmäßig wird 3.10.13 Installiert
    - Analyzer um Netzwerkmitschnitte von Wireshark zu analysieren

## Umgebung
- Alle Daten wurden auf einer speziellen Debian VM aufgenommen
- Alle Aufnahmen waren 10 Minuten lang bis auf das Grundrauschen
- Für Testdurchführungen wurde die Urpsrüngliche VM geklont, die Tests durchgeführt und der Klon gelöscht
- VM war auf NAT Netzwerk eingestellt