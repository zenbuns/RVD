# 🔒 Vulnerability Database

## 🎯 Eesmärk

Luua andmebaas, kuhu on salvestatud hetkel teadaolevad haavatavused, nende mõjud meie süsteemidele, hinnangud ja leevendusmeetmed.

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

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

3. 📄 Järgi ekraanil kuvatavaid juhiseid.
4. 🔁 Peale paigaldamist lisa Rust oma PATH-i, taaskäivitades terminali või käivitades:

source $HOME/.cargo/env

### 📥 Juhised

1. **📥 Lae alla andmed:**
   - - Lae alla allitems1.csv fail siit: [Google Drive'i link](https://drive.google.com/file/d/16KYLZWWH6ZoHptPvI5vbnud3U3TVIlPd/view?usp=sharing)


2. **📂 Paiguta CSV fail:**
   - Aseta allalaaditud allitems1.csv fail projekti kausta src/db

3. **🔨 Ehita projekt:**
   - Ava terminal projekti juurkaustas ja käivita:

cargo build

### 🚀 Projekti käivitamine

Peale ehitamist saad projekti käivitada käsuga:

cargo run


## 📄 Litsents

See projekt on litsentseeritud MIT litsentsi alusel.
