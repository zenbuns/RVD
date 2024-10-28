# 🔒 Robot Vulnerability Database

## 🎯 Eesmärk

Luua andmebaas, kuhu on salvestatud hetkel teadaolevad haavatavused, nende mõjud meie robotile, hinnangud ja leevendusmeetmed.

## ⚙️ Funktsioonid

- **🔄 Automatiseeritud andmebaasi uuendus** läbi National Vulnerability Database (NVD) API, et tagada kõige värskemad ja kriitilisemad andmed.
- **🚨 Teavitussüsteem** kriitiliste haavatavuste jaoks, et informeerida kiirelt vastavaid osapooli.
- **📊 Visualiseerimine ja analüüs** tööriistade abil, et paremini mõista trende ja prioriteete.

## 🗂️ Näidisandmed

~~Lisatud on näidisandmed, et simuleerida realistlikumat andmebaasi, kuna hinnangud ja leevendusmeetmed võivad puududa.~~

## 🛠️ Paigaldusjuhend

### ✅ Eeldused

- **🦀 Rust**: Veendu, et Rust on sinu arvutisse paigaldatud.

### 💾 Rust paigaldamine (kiireim meetod PC või Linux jaoks)

1. 🖥️ **Ava terminal**
2. ⚡ **Käivita järgmine käsk** Rust'i paigaldamiseks `rustup` abil:

```curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh ```

3. 📄 Järgi ekraanil kuvatavaid juhiseid.
4. 🔁 Peale paigaldamist lisa Rust oma PATH-i, taaskäivitades terminali või käivitades:

```source $HOME/.cargo/env```

### 📥 Juhised

1. **📥 Lae alla andmed:**
   - - Lae alla allitems1.csv fail siit: [Google Drive'i link](https://drive.google.com/drive/folders/1Hqbxx2ldE29QNn28GbQ3393t_vz0Wz30)


2. **📂 Paiguta CSV fail:**
   - Aseta allalaaditud allitems1.csv fail projekti kausta ```src/db```

3. **🔨 Ehita projekt:**
   - Ava terminal projekti juurkaustas ja käivita:

```cargo build```

### 🚀 Projekti käivitamine

Peale ehitamist saad projekti käivitada käsuga:

```cargo run```

# 📋 TODO List

## ✅ Teostatud Funktsionaalsused

### 🗄️ Andmebaas
- [x] SQLite andmebaasi implementatsioon
- [x] Andmebaasi põhistruktuur
- [x] CSV faili importimise funktsionaalsus
- [x] Põhilised andmebaasi päringud
- [x] Laisa laadimise (lazy loading) implementeerimine
- [x] Leheküljepõhine andmete laadimine (pagination)
- [x] Vahemälu süsteemi põhistruktuur
- [x] Andmebaasi indekseerimine

### 🔍 Otsing ja Filtreerimine
- [x] Otsingu põhifunktsionaalsus
- [x] Kuupäeva filter
- [x] Riskitaseme filter
- [x] CVE ID filter
- [x] Statistika visualiseerimine

### 🤖 Robotiteinventuur
- [?] Andmebaasi integratsioon
- [x] Kasutajaliidese põhi

## 🚧 Tegemist Vajavad Tööd

### 🗃️ Andmebaasi Optimeerimised
- [ ] Kohandatud vormide jõudluse parandamine
- [ ] Suurte ühendusoperatsioonide (JOIN) optimeerimine
- [ ] Vahemälu strateegia täiustamine
- [ ] Päringute optimeerimine üle 320000 kirje korral
- [ ] Roboti andmete lisamine ja töötlemine läbi GUI

### ⚠️ Häiresüsteem
- [ ] Automaatne haavatavuste kontroll
- [ ] Teavitussüsteemi implementatsioon
- [ ] Tarkvara ristkontrolli funktsionaalsus
- [ ] Häirete prioritiseerimine
- [ ] E-posti teavituste seadistamine

## 🐛 Teadaolevad Vead
- [ ] Suured andmebaasi operatsioonid põhjustavad viivitusi

## 📅 Järgmised Prioriteedid
1. Robotite inventuuri jõudluse optimeerimine
2. Häiresüsteemi põhifunktsionaalsuse implementeerimine
3. Andmebaasi päringute optimeerimine



See projekt on litsentseeritud MIT litsentsi alusel.
