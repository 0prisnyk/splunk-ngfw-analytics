# Комплексна аналітика журналів NGFW у Splunk

Цей репозиторій містить ресурси для відтворення системи комплексної аналітики на основі журналів подій Next-Generation Firewall (NGFW). Проєкт реалізовано на платформі **Splunk** з використанням **Splunk Dashboard Studio**.

## Опис проєкту

Метою проєкту є розробка підходу до комплексного аналізу журналів NGFW для покращення процесу виявлення загроз. Система включає механізми збагачення вихідних логів даними з зовнішніх джерел та їх подальшу візуалізацію на інтерактивному дашборді.

## Структура дашборду

Дашборд має дворівневу структуру і складається з наступних вкладок:

1. **Вкладка загального аналізу трафіку та збагаченої інформації**
   - Надає загальний огляд мережевої активності.
   - Візуалізує дані про публічні IP-адреси джерела та призначення з їхніми рейтингами TI.
   - Відображає географічний розподіл комунікацій, топ доменів, додатків та статистику за діями NGFW.

2. **Вкладка детального аналізу загроз**
   - Призначена для глибокого аналізу подій, ідентифікованих як загрози.
   - Відображає розподіл загроз за рівнями серйозності та вердиктами TI.
   - Показує динаміку загроз у часі та надає детальну таблицю для розслідування інцидентів.

## Як відтворити

### Крок 1: Передумови

1. Встановлена та налаштована платформа **Splunk Enterprise**.
2. Встановлені додатки з Splunkbase:
   - **AbuseIPDB App for Splunk**
   - **VT4Splunk (VirusTotal App)**
3. Отримані та налаштовані **API ключі** для AbuseIPDB та VirusTotal у відповідних додатках.

### Крок 2: Завантаження даних

1. Підготуйте власні журнали NGFW у форматі **CSV**.
2. У веб-інтерфейсі Splunk перейдіть до `Settings > Add Data`.
3. Завантажте ваш CSV-файл, вказавши для нього `sourcetype=csv`.
4. Створіть новий індекс з назвою `ngfw` та збережіть дані в нього.

### Крок 3: Створення розрахункових полів (Calculated Fields)

Перейдіть до `Settings > Fields > Calculated Fields` та створіть два поля:

- **dest_ip_type**:
  ```splunk
  if(cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("127.0.0.0/8", dest_ip) OR cidrmatch("169.254.0.0/16", dest_ip), "private", "public")
  ```

- **src_ip_type**:
  ```splunk
  if(cidrmatch("10.0.0.0/8", src_ip) OR cidrmatch("192.168.0.0/16", src_ip) OR cidrmatch("172.16.0.0/12", src_ip) OR cidrmatch("127.0.0.0/8", src_ip) OR cidrmatch("169.254.0.0/16", src_ip), "private", "public")
  ```

### Крок 4: Створення та налаштування лукапів

#### 4.1 Статичний лукап

- Імпортуйте файл `suspicious_countries.csv` у Splunk.

#### 4.2 Динамічні лукапи

##### `ip_candidates.csv`

```splunk
index=ngfw (src_ip_type=public OR dest_ip_type=public)
| eval ip1=if(src_ip_type="public", src_ip, null())
| eval ip2=if(dest_ip_type="public", dest_ip, null())
| table ip1 ip2
| eval ip=mvappend(ip1, ip2)
| mvexpand ip
| search ip=*
| dedup ip
| table ip
| outputlookup ip_candidates.csv
```

##### `public_ips_location.csv`

```splunk
| inputlookup ip_candidates.csv
| iplocation ip
| table ip, Country
| outputlookup public_ips_location.csv
```

##### `final_TI_info.csv`

###### 4.2.1 Збагачення через AbuseIPDB

```splunk
| inputlookup ip_candidates.csv
| abuseipdbcheck ip=ip
| table ip, abuseConfidenceScore, domain
| outputlookup final_TI_info.csv
```

###### 4.2.2 Збагачення через VirusTotal (запланований пошук)

```splunk
| inputlookup final_TI_info.csv
| append [
    | inputlookup final_TI_info.csv
    | where isnull(vt_detections)
    | head 1
    | vt4splunk ip=ip
]
| stats latest(*) as * by ip
| fields ip, abuseConfidenceScore, domain, vt_detections, vt_total_engines
| outputlookup final_TI_info.csv append=false
```

###### 4.2.3 Фіналізація TI-інформації

```splunk
| inputlookup final_TI_info.csv
| fillnull value="N/A" domain
| eval vt_percentage_score=(vt_detections/vt_total_engines)*100, vt_percentage_score=round(vt_percentage_score, 2)
| eval VT_verdict = case(vt_percentage_score==0, "0", (vt_percentage_score>0 AND vt_percentage_score<10), "1", vt_percentage_score>=10, "2")
| eval AbuseIPDB_verdict = case(abuseConfidenceScore==0, "0", (abuseConfidenceScore>0 AND abuseConfidenceScore<20), "1", abuseConfidenceScore>=20, "2")
| eval Highest_TI_verdict_score = if(AbuseIPDB_verdict>VT_verdict, AbuseIPDB_verdict, VT_verdict)
| eval TI_verdict = case(Highest_TI_verdict_score==0, "Harmless", Highest_TI_verdict_score==1, "Suspicious", Highest_TI_verdict_score==2, "Malicious")
| table ip domain abuseConfidenceScore AbuseIPDB_verdict vt_detections vt_total_engines vt_percentage_score VT_verdict Highest_TI_verdict_score TI_verdict
| outputlookup final_TI_info.csv
```

### Крок 5: Налаштування автоматичних лукапів

Перейдіть до `Settings > Lookups > Automatic lookups` та створіть чотири правила:

1. **Геолокація `src_ip`**:
   - Lookup table: `public_ips_location.csv`
   - Input: `ip = src_ip`
   - Output: `Country = src_geo_country`

2. **Геолокація `dest_ip`**:
   - Lookup table: `public_ips_location.csv`
   - Input: `ip = dest_ip`
   - Output: `Country = dest_geo_country`

3. **TI-дані `src_ip`**:
   - Lookup table: `final_TI_info.csv`
   - Input: `ip = src_ip`
   - Output:
     - `TI_verdict = src_TI_verdict`
     - `abuseConfidenceScore = src_AbuseIPDB_score`
     - `vt_percentage_score = src_VT_percentage_score`
     - `domain = src_domain`

4. **TI-дані `dest_ip`**:
   - Lookup table: `final_TI_info.csv`
   - Input: `ip = dest_ip`
   - Output:
     - `TI_verdict = dest_TI_verdict`
     - `abuseConfidenceScore = dest_AbuseIPDB_score`
     - `vt_percentage_score = dest_VT_percentage_score`
     - `domain = dest_domain`

### Крок 6: Створення типів подій (Event Types)

Перейдіть до `Settings > Event types` та створіть чотири типи подій з відповідними запитами та пріоритетами:

- **Malicious** (Пріоритет: 1):
  ```splunk
  index=ngfw (src_TI_verdict="Malicious" OR dest_TI_verdict="Malicious")
  ```

- **Suspicious** (Пріоритет: 2):
  ```splunk
  index=ngfw (src_TI_verdict="Suspicious" OR dest_TI_verdict="Suspicious") AND NOT (src_TI_verdict="Malicious" OR dest_TI_verdict="Malicious")
  ```

- **Harmless** (Пріоритет: 3):
  ```splunk
  index=ngfw (src_TI_verdict="Harmless" OR dest_TI_verdict="Harmless") AND NOT (src_TI_verdict="Malicious" OR dest_TI_verdict="Malicious" OR src_TI_verdict="Suspicious" OR dest_TI_verdict="Suspicious")
  ```

- **Unknown** (Пріоритет: 4):
  ```splunk
  index=ngfw NOT (src_TI_verdict=* OR dest_TI_verdict=*)
  ```

### Крок 7: Імпорт дашборду

1. Перейдіть до розділу `Dashboards` у Splunk.
2. Натисніть `Create New Dashboard`.
3. Виберіть **Dashboard Studio**.
4. Відкрийте вкладку `Source` (</>).
5. Вставте вміст файлу `ngfw_analytics_dashboard.json` з репозиторію.
6. Збережіть дашборд.

Після цього дашборд буде готовий до використання та автоматично заповниться даними після запуску пошуків і формування лукапів.
