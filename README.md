Entwicklung einer Architektur zum Federated Learning zur

Verhinderung von Datenmanipulation

#### Bachelorarbeit

```
Informatik und Wirtschaftsinformatik
```
```
Technische Hochschule Würzburg-Schweinfurt
```
eingereicht bei:

Prof. Dr. Sebastian Biedermann

eingereicht von:

Mario von Bassen ( 6120069 )

Studiengang: Bachelor of Science E-Commerce (B.Sc.)

Anschrift: Gressengasse 1, 97070, Würzburg

Telefon: 01577 /

E-Mail: mario.vonbassen@student.thws.com

Würzburg, den 08.08.


## Inhaltsverzeichnis


- 1 Einführung und aktueller Stand Künstlicher Intelligenz
   - 1.1 Ziel dieser Arbeit
   - 1.2 Aufbau und Struktur dieser Arbeit
- 2 Einführung Federated Learning
   - 2.1 Konzept und Terminologie eines Federated Learning Systems
      - 2.1.1 Ausprägungen von Federated Learning Systemen
      - 2.1.2 Vorteile und Möglichkeiten von Federated Learning
      - 2.1.3 Nachteile und Herausforderungen von Federated Learning...................................................
- 3 Cyberattacken auf Künstliche Intelligenz
      - 3.1 Adversarial Attack
      - 3.2 Data Poisoning
      - 3.3 Label Flipping Attack
      - 3.4 Backdoor Attack
      - 3.5 Fidelity Extraction Attack
      - 3.6 Accuracy Extraction Attack
      - 3.7 Model Extraction Attack
      - 3.8 Man-in-the-middle Attack
- 4 Cyberattacken auf Federated Learning
      - 4.1 Data Poisoning Attack in Federated Learning
      - 4.2 Backdoor Attacks in Federated Learning
      - 4.3 Denial of Service Attacks in Federated Learning
      - 4.4 Free-rider Attack
      - 4.5 Gradient Leakage Attack
      - 4.6 Sybil Attacks
      - 4.7 Defensive Schutzmaßnahmen des Proof-of-Concept
- 5 Angriffssimulation auf ein Federated Learning System.......................................................................
   - 5.1 Begriffe und Definitionen
- 6 Einführung und Ziel der Testdurchführungen
   - 6.1 Versuchsaufbau nach dem Paper
      - 6.1.1 Datensatz
      - 6.1.2 Ziel des Angreifers
      - 6.1.3 Angriffsmethode Label Flipping
      - 6.1.4 Resultate und Ergebnisse des Papers
   - 6.2 Eigenständige Durchführung des Experiments
      - 6.2.1 Einführung und Testmethodik
      - 6.2.3 Ermittlung des Basis Set-Up
      - 6.2.4 Erhöhung der Poisoning-Rate, Auswirkung auf Modell-Performance...................................
      - 6.2.5 Auswirkung der Modell-Performance bei Steigerung der Poisoning Rate
      - 6.2.6 Validierung und Interpretation eigene Testdurchführung
      - 6.2.7 Optimale Parameter-Einstellungen für das Basis Set-Up
- 7 Einführung Blockchain
- 8 Blockchain und Federated Learning
   - 8.1 Blockchain Federated Learning Architekturen
   - 8.2 Vorteile von BCFL
   - 8.3 Nachteile von BCFL
   - 8.4 Warum Blockchain im Proof-of-Concept
- 9 Technologien im Proof-of-Concept
   - 9.1 Ethereum
   - 9.2 Ganache
   - 9.3 Python
      - 9.3.1 Tensorflow
      - 9.3.2 Python Sockets
- 10 Proof of Concept
   - 10.1 Beschreibung des Proof-of-Concept
   - 10.2 Funktionale und nicht-funktionale Anforderungen des Proof of Concept
      - 10.2.1 Sicherheit
      - 10.2.2 Zuverlässigkeit
      - 10.2.3 Leistung (Effizienz und Latenz)
      - 10.2.4 Skalierbarkeit
      - 10.2.5 Kompatibilität
      - 10.2.6 Benutzerfreundlichkeit
   - 10.3 Einsatzgebiete, Szenarien und Möglichkeiten des Proof-of-Concept
      - 10.3.1 Beispielszenario medizinische Einrichtung
- 11 Topologie und Struktur - Proof of Concept
      - 11.1 Gateway-Server
      - 11.2 Aggregate-Server
      - 11.3 Client
      - 11.4 Smart Contract
      - 11.5 Daten, Preprocessing und Non-IID
      - 11.6 Hashing-Algorithmus..............................................................................................................
      - 11.7 Hash-based Message Authentication Code
      - 11.8 Public-Private-Key Verfahren
      - 11.9 Digitale Zertifikate
      - 11.10 Advanced Encryption Standard
      - 11.11 Server Model Encoding (Verschlüsselung des ML/DL-Modells)


```
11.12 Client Validierung ................................................................................................................. 70
11.13 Defensive Maßnahmen gegen eine Label Flipping Attack ................................................... 72
11.14 Erstellung des Deep Learning Modells ................................................................................. 78
11.15 PoC-Aufbau und System-Ablauf ........................................................................................... 79
```
12 Evaluation und Ergebnisse des Proof-of-Concept ............................................................................. 86

```
12.1 Durchführung der Label Flipping Attack am Datensatz .............................................................. 86
12.2 Ergebnisse und Resultate des Proof-of-Concept ....................................................................... 87
12.2.1 PoC-Testdurchlauf .............................................................................................................. 87
12.3 Performance-Vergleich Basis Set-Up und PoC ........................................................................... 90
```
13 Optimierungsmöglichkeiten des Proof-of-Concept .......................................................................... 93

14 Fazit und Ausblick ............................................................................................................................. 96

15 Literaturverzeichnis .......................................................................................................................... 98

Eidesstaatliche Erklärung ..................................................................................................................... 104

# Abkürzungsverzeichnis

```
PoC Proof-of-Concept
FL Federated Learning
ML Machine Learning
DL Deep Learning
PoW Proof-of-Work
KI Künstliche Intelligenz
IoT Internet of Things
GMA Global Model Accuracy
GMR Global Model Recall
GC1A/GC9A Global Class 1/9 Accuracy
GC1R/GC9R Global Class 1/9 Recall
```
Link zum Code des Proof-of-Concept: https://github.com/Mvb-DL/SickurityFLee

Live Demo des Proof-of-Concept: https://drive.google.com/file/d/1pfVpSGqYyJHT-
C64jqgjl4obee33J0El/view?usp=sharing


## 1 Einführung und aktueller Stand Künstlicher Intelligenz

Lange Zeit war nicht abzuschätzen, welchen Einfluss die Künstliche Intelligenz (KI) auf unseren Alltag
und unsere Arbeit nehmen wird. Der Ausbau von KI, in Hinblick auf ihre technische Umsetzung,
durchlief eine Vielzahl von verschiedenen Entwicklungsstadien, wobei diese Entwicklung viele Höhen
und Tiefen zu verzeichnen hatte [1].

Seit der Einführung von Chat-GPT hat sich jedoch der Fokus und das wirtschaftliche Bestreben der KI-
Entwicklung stark verändert.

Systeme wie Chat-GPT stellen uns als Gesellschaft und Einzelpersonen im Bereich ethischer und
rechtlicher Fragen, vor allem in Bezug auf Datenschutz und Urheberrecht, vor große
Herausforderungen. Oft sind die gesellschaftlichen Herausforderungen größer als die technischen,
denn bereits heute fürchten viele Arbeitnehmer, dass ihre Arbeit in der Zukunft durch KI stark
verändert oder sogar ersetzt wird [2].

Diese Probleme wurden allerdings früh von Unternehmen und Staaten erkannt. Es wurden Ideen und
Ansätze entwickelt, um dieser Problematik entgegensteuern zu können und die Pfeiler für eine
technologische Entwicklung in die richtige Richtung zu setzen.

Ethische Fragen und Definitionen in Bezug auf KI werden bereits von der EU in verschiedenen
Gesetzesgrundlagen formuliert [3]. Darüber hinaus werden diverse Ansätze entwickelt den
Datenschutz in Einklang mit der Entwicklung der KI zu bringen. Es bedarf also vieler Innovationen und
Ansätze in diesem Bereich, um den Herausforderungen entgegenwirken zu können.

### 1.1 Ziel dieser Arbeit

Wie bereits im ersten Teil dargestellt, gibt es innerhalb der EU einen aktuellen Diskurs, der viele
Technologien und Anwendungen im Bereich der KI hinsichtlich ethischer und rechtlicher Fragen auf
den Prüfstand stellt.

Es zeichnet sich ab, dass die Anwendung von KI-Applikationen, die u.a. personenbezogen Daten
verarbeiten, fester Bestandteil des täglichen Gebrauchs in Arbeit – und Privatleben von Nutzenden
wird. Unter diesem Aspekt wird es womöglich eine noch größere Herausforderung darstellen, Daten,
die besonders sensitiv sind, wie Krankendaten, Militärdaten, Bankdaten usw. anhand eines KI-Systems
zu verarbeiten. Vor allem würden medizinische Einrichtungen von der Verwendung KI gestützter
Systeme profitieren (vgl. Einsatzgebiete, Szenarien und Möglichkeiten des Proof-of-Concept). Es gibt
bereits eine Vielzahl an Entwicklungen und Ansätzen, die große Vorteile für die Arbeit innerhalb dieses
medizinischen Bereichs aufzeigen, wie z. B. das Erstellen von Literatur im medizinischen Bereich [4].

Da zur Entwicklung derartiger Systeme jedoch eine gewisse Anzahl an Daten vorhanden sein muss,
scheitern viele Ideen bereits an dieser Hürde. Zudem sind viele medizinische Einrichtungen bereits
stark an Personal unterbesetzt und einer großen Anzahl an Cyberattacken vor allem während der
Coronakrise ausgesetzt [5]. Das additive Hinzufügen zusätzlicher Technologien, die gewartet und
gesichert werden müssen, würde nicht zwingend eine Lösung für derartige Einrichtungen darstellen.
Es sei denn, die Vorteile des jeweiligen Systems bzw. der Technologie würden den hohen
Wartungsaufwand rechtfertigen.

Einen dieser Lösungsansätze dazu bietet womöglich das Federated Learning (vgl. Einführung
Federated Learning). Im Jahr 2016 veröffentlicht, zog es eine größere Anzahl an Grundlagenforschung
zu diesem Thema nach sich. Beispielsweise um Antworten auf die Frage zu finden, ob ein derartiges
System helfen kann, Cyberattacken auf Daten und KI-Modelle zu reduzieren und dazu gleichzeitig in
der Lage ist die Datenschutzbestimmungen einzuhalten [6].


Trotz einer Vielzahl von Untersuchungen ist die Anzahl praktischer Umsetzungen derartiger FL-
Systeme im Verhältnis zu anderen Entwicklungen in der KI sehr gering und in manchen Bereichen noch
weit davon entfernt im Arbeitsalltag oder innerhalb von Unternehmen eingesetzt werden zu können
[7]. Hinzu kommt die Bedrohung von Cyberattacken auf KI-Systeme, welche die gesamte KI-
Entwicklung betrifft und stark ausbremsen kann.

Die Forschung und Erfahrung zu derartigen Attacken auf KI-Systemen sind in der wissenschaftlichen
Untersuchung ebenfalls noch nicht allzu weit fortgeschritten [8] und es zeigt sich weiterhin, dass das
Aufdecken und die Prävention solcher Angriffe eine Herausforderung darstellen.

Der Umstand, dass Cyberattacken auf KI-Systeme bzw. FL-Systeme theoretisch noch nicht
abschließend untersucht wurden und die Tatsache, dass nur wenige praktische Umsetzungen von FL-
Systemen existieren, werfen grundlegende Fragen auf, welche anhand dieser Arbeit erörtert werden
sollen. Dabei ist es das Ziel der Arbeit einen Proof-of-Concept (PoC) zu entwickeln (praktische
Umsetzung), welcher präventiv spezifische Cyberattacken annullieren und darüber hinaus theoretisch
und anhand von Testdurchläufen weiter Erkenntnisse über Cyberattacken in Bezug auf das Federated
Learning erschließen soll (theoretische Umsetzung).

Dieser PoC soll demnach dazu dienen, Erfahrungen und weitere Herausforderungen innerhalb des
Federated Learning aufzudecken, welche es späteren Forschungsgruppen erlauben soll, Erkenntnisse
daraus zu ziehen und weitere Optimierungen durchzuführen.

Das Ziel des PoC ist es vorrangig die Datenintegrität innerhalb des Systems zu sichern (vgl. Abschnitt
Sicherheit) und die einzelnen teilnehmenden Akteure im System zu identifizieren. Darüber hinaus
anhand der Tatsache, dass Angriffe auf KI-Systeme rückwirkend schwierig aufzudecken sind, soll die
Möglichkeit durch den PoC bestehen, derartige Angriffe präventiv zu verhindern und zu versuchen
nachträgliche Manipulationen gewissen Akteuren zuordnen zu können. Inwiefern die Blockchain-
Technologie bei der Umsetzung behilflich sein kann, wird u.a. im Abschnitt Einführung Blockchain
näher erläutert.

### 1.2 Aufbau und Struktur dieser Arbeit

Der Aufbau der Arbeit orientiert sich an dem oben beschriebenen Ziel. Zunächst gibt es eine
Einführung in das Federated Learning. Auf eine allgemeine Einleitung in die Thematik der Künstlichen
Intelligenz, vor allem auf die Kernbereiche Machine - und Deep Learning wird bewusst verzichtet, um
den Fokus auf das Wesentliche, der Erklärung und Beschreibung des PoC, zu legen. Dennoch werden
notwendige Begrifflichkeiten und Definition, so wie sie u.a. innerhalb der Testdurchführung (vgl.
Einführung und Ziel der Testdurchführungen) dargestellt werden, vorab definiert, erklärt und
eingeordnet. Des Weiteren werden bei der Einführung über Federated Learning die Vor -und
Nachteile sowie Herausforderungen dieser Technologie geschildert. Dieser Abschnitt, leitet über in
den allgemeinen Teil der Cyberangriffe auf KI, wobei dieser Abschnitt wiederum auf spezielle Angriffe
innerhalb von FL-Systemen verweist.

Der folgende Teil umfasst die Testdurchführung eines simulierten Angriffs auf ein FL-System. Dabei
wird vorab anhand eines Papers untersucht, wie allgemeine Angriffe auf ein FL-System ablaufen
können und notwendige Begriffe definiert. Es werden die einzelnen Resultate des Papers im Anschluss
interpretiert.

Die gewonnenen Erkenntnisse werden auf die Erstellung eines eigenen FL-Systems übertragen und
eigenständige Testdurchläufe durchgeführt. Dies dient als Validierungsgrundlage, um einerseits
notwendige Parameter näher zu beschreiben und zu definieren, die einen Einfluss auf die defensiven
Maßnahmen eines FL-Systems haben können und andererseits als ein Vorher-Nachher-Vergleich,
inwiefern der PoC eine Verbesserung der Modell-Performance trotz eines Angriffs erreichen kann. Der
Abschnitt endet mit der Auswertung und Interpretation dieser einzelnen Testdurchläufe.


Da der PoC unter anderem eine Blockchain verwendet, erfolgt eine kurze Einführung in die Blockchain-
Technologie, sowie ein Abschnitt, welcher die Kombination von Blockchain und Federated Learning
beschreibt, wobei hier Ideen und Konzepte, sowie Vor- und Nachteile bei der Kombination beider
Technologien aufgezeigt werden.

Bevor der PoC beschrieben wird, werden noch die einzelnen Technologien, die bei der Erstellung des
PoC verwendet wurden, vorgestellt. Es folgen die Systembeschreibung und Zielsetzungen sowie die
möglichen Einsatzszenarien des PoC. Weiter werden die einzelnen Bestandteile des PoC und die
konkreten Umsetzungen, u.a. durch den dargestellten Programmcode vermittelt, wobei der
vollständige Code des PoC innerhalb der Arbeit hier ausgespart wird und unter folgendem Link:
_https://github.com/Mvb-DL/SickurityFLee_ einzusehen ist.

Um den PoC besser nachvollziehen zu können, folgt eine stufenweise Beschreibung des
Programmablaufs, welche anhand von Diagrammen noch einmal verständlicher dargestellt wird.

Es folgt eine Testdurchführung des PoC und ein Performance-Vergleich aus den vorab durchgeführten
Testergebnissen mit den Testergebnissen des PoC. Abschließend gibt es einen Einblick, welche
Verbesserungsmöglichkeiten der PoC umfasst und endet mit einem Fazit und Ausblick in Bezug auf
mögliche Entwicklungen des PoC und der KI allgemein.

## 2 Einführung Federated Learning

Das Federated Learning (FL) wurde 2016 von Google entwickelt und sollte eine Möglichkeit darstellen,
viele verschiedene Geräte und Teilnehmer an einem Machine Learning Modell partizipieren zu lassen,
so dass jeder dieser Teilnehmer durch das Einbringen seiner Daten voneinander profitieren kann [9].

Innerhalb von Federated Learning gibt es keine zentrale Server-Instanz, welche die Daten aller
Teilnehmer (Clients) zentral bei sich speichert und dann mit diesen Daten trainiert, sondern das
eigentliche Training wird auf den Geräten bzw. auf Seiten der Clients durchgeführt.

Dies hat mehrere Vorteile, was im Abschnitt Vorteile und Möglichkeiten von Federated Learning näher
betrachtet wird. Dieses clientseitige Training ist vor allem in Bereichen der Medizin und innerhalb der
Verwendung von IoT-Geräten interessant, da die Daten das Gerät bzw. die Einrichtungen nicht
verlassen und diese Daten nicht von externen Entitäten verarbeitet werden. Auch Smartphones,
Smartwatches und ähnliche Mobilgeräte können von einer derartigen Architektur profitieren, da es
nicht notwendig ist, die gesamte Zeit mit einem Server verbunden zu sein, sondern auch ohne eine

### direkte bestehende Verbindung ihre internen Systeme optimieren und updaten können.

### 2.1 Konzept und Terminologie eines Federated Learning Systems

Folgende Begriffe wie Modellgewichte u. Ä. werden in Abschnitt Begriffe und Definitionen erläutert.

Innerhalb eines FL-Systems gibt es einen sog. _Aggregate-Server_ und mehrere _Clients_ , wobei es im
Spezifischen eine Anzahl von 𝐾 Clients in einem System gibt. Dabei verwendet ein Client 𝑘 jeweils ein
Gerät, wobei dann 𝑘∈𝐾 [10]_._

Jedes/jeder der partizipierenden Geräte bzw. Clients im System verwendet auch das gleiche ML/DL-
Modell, welches durch den Aggregate-Server zur Verfügung gestellt worden ist. Es ist vorerst
unerheblich für die Durchführbarkeit und Prinzip des FL-Systems, welche Art von Modell (Machine -
oder Deep Learning) oder welcher Datentyp im Datensatz verwendet wird.

Jeder Client bzw. dessen Gerät verwendet zwar das identische ML/DL-Modell, jedoch greift jeder
Client auf seinen eigenen individuellen lokalen Datensatz zu, beschrieben durch 𝐷𝑘∈𝐾 [10]_._


```
Nachdem individuellen Training der Clients mit ihren
Daten, werden die Modellgewichte (vgl. Begriffe und
Definitionen) an den Aggregate-Server übermittelt.
Der Aggregate-Server aggregiert dann diese
Modellgewichte der Clients und erstellt ein neues
sogenanntes globales Modell.
```
Für das Aggregieren wird in der Regel der
Federated Averaging Algorithmus verwendet
(vgl. Federated Averaging Algorithmus) [11].

```
Nach der erfolgreichen Aggregierung der
einzelnen Modellgewichte und dem Erstellen des
globalen Modells werden die Modellgewichte
wieder an die Clients zurück übermittelt und die
Geräte aktualisieren ihr vorliegendes Modell
anhand der neuen Modellgewichte. Im Anschluss
beginnt der Prozess wieder von vorne, solange
wie der Zentrale Server bzw. der Aggregate-
Server es vorgibt.
```
```
Abbildung 1 : Einer der ersten Schritte eines FL-Systems
umfasst das Versenden des globalen Modells an die
Clients [Quelle: Eigene Darstellung].
```
```
Abbildung 2 :Im Anschluss werden die trainierten Modellgewichte von den
Clients wieder zum Aggregate-Server gesendet [Quelle: Eigene Darstellung].
```
```
Abbildung 3 : Der letzte Schritt umfasst das Aggregieren der
Modellgewichte, welche im Anschluss wieder an die Clients
übermittelt werden [Quelle: Eigene Darstellung].
```

Dies beschreibt den Ablauf innerhalb eines grundlegenden FL-Systems. Mittlerweile gibt es jedoch
eine Vielzahl von Varianten, unterschiedlichen Aggregation-Algorithmen und Architekturen (vgl.
Topologie und Struktur - Proof of Concept), welche für spezifische Zwecke und Umgebungen
eingesetzt werden können. Manche Architekturen eignen sich dabei für bestimmte Zwecke besser als
andere.

#### 2.1.1 Ausprägungen von Federated Learning Systemen

Durch die immer weiter fortschreitende Entwicklung im Bereich des Federated Learning, gibt es
mittlerweile mehrere verschiedene Ansätze und Architekturen [12],wie ein FL-System genau
aufgebaut ist.

1. Vertikales Federated Learning

```
Im vertikalen Federated Learning haben die Clients jeweils einen Datensatz mit
unterschiedlichen Merkmalen (Features), aber gemeinsamen Beispielinstanzen. Im Paper
„Federated Learning: Opportunities and Challenges“ [12] sind als Beispiel zwei Clients
aufgeführt, welche über Daten der gleichen Personengruppe, aber mit anderen Attributen (z.
B. Haar -und Augenfarbe) verfügen. So können sich die Clients zusammenschließen und
gemeinsam auf den geteilten Daten lernen bzw. ihre Modelle trainieren.
```
2. Horizontales Federated Learning

```
Diese Art des Federated Learning ist der vertikalen Ausprägung ähnlich, wobei die Clients
jeweils über einen Datensatz mit gleichen Merkmalen, aber unterschiedlichen
Beispielinstanzen verfügen. In Bezug auf das bereits ausgeführten Daten des vertikalen FL,
bedeutet das, dass die Clients eine unterschiedliche Personengruppe innerhalb ihrer Daten
hinterlegt haben, aber diese Personengruppen jeweils über die gleichen Merkmale verfügen.
```
3. Federated Transfer Learning

```
Bei Federated Transfer Learning wird ein vortrainiertes Modell als Basis genommen und dann
über ein föderiertes Netzwerk von Geräten oder Datensätzen mit zusätzlichen Daten weiter
trainiert. Diese Methode ist besonders nützlich, wenn neue Merkmale oder Daten hinzugefügt
werden sollen, die ähnlich, aber nicht identisch mit den ursprünglichen Trainingsdaten sind.
```
4. Cross-Silo Federated Learning

```
Diese Art des Federated Learning wird dann verwendet, wenn in dem vorliegenden FL-System
eher wenige, aber große Clients partizipieren. Dabei kann es sich um eine vertikale oder
horizontale FL-Architektur handeln und wird oft an die Organisation angepasst, in der das FL-
System verwendet wird.
```
5. Cross-Device Federated Learning

```
Die in dieser Auflistung letzte Ausprägung des Federated Learning ist das Cross-Device
Federated Learning. In einem dezentralen System, mit unterschiedlichen Teilnehmern, ist es
nicht immer möglich, dass alle Clients den gleichen Gerätetypus verwenden. Daher ist es
notwendig für manche FL-Systeme mit einer breiten Varianz an unterschiedlichen Geräten
umgehen und arbeiten zu können bzw. sich diesen Unterschieden anzupassen.
```

#### 2.1.2 Vorteile und Möglichkeiten von Federated Learning

Ein großer Vorteil, welcher durch das Anwenden von Federated Learning entsteht, ist die Möglichkeit,
eine große Varianz an verschiedenen Teilnehmern in einem System zu erreichen. Eine derartige
Vielfalt kann auch für eine dementsprechende Varianz innerhalb der Daten sorgen, was wiederum zu
einem besseren Ergebnis eines KI-Modells führen kann [13].

Vor allem für Bereiche in welchem viele verschiedene Geräte, wie Messstationen, Smartphones oder
andere IoT-Devices verwendet werden, kann es durchaus von Vorteil sein, ein dezentrales flexibles
System zu etablieren, welches sich demnach an äußere Faktoren wesentlich schneller anpassen kann.
So ist es wesentlich effektiver, mit realen Umweltdaten zu arbeiten (z. B. Messwerte einer
Smartwatch, die dann umgehend mit in das allgemeine, globale Training miteinfließen), als das
Verwenden von Daten einer zentralen Server-Instanz, welche in der Regel ortsgebunden sind.

Einer der größten Vorteile von Federated Learning ist aber vor allem die Einhaltung des Datenschutzes
und der Privatsphäre (vgl. Federated Learning und Datenschutz). Da in einem FL-System die
eigentlichen Trainingsdaten bzw. die oftmals sensitiven personenbezogene Daten (z. B. bei einem EKG
in Form einer Smartwatch), das Gerät nicht verlassen, sondern immer nur das Ergebnis des jeweiligen
lokalen Trainings bzw. die Modellgewichte versendet werden, über die man in keinem angemessenen
Aufwand auf die eigentlichen Gerätedaten schließen kann, können Aspekte des Datenschutzes schon
aufgrund der Architektur von Federated Learning zu teils eingehalten werden [14].

So ist es für Einrichtungen aus dem medizinischen, finanziellen oder militärischen Bereich möglich,
anhand eines FL-Systems zu kooperieren und so an den Daten aller Einrichtungen zu profitieren, ohne
aber die eigenen Daten zu veröffentlichen. Dies ist wichtig, da es für viele Einrichtungen aufgrund
rechtlicher und wirtschaftlich bedingter Umstände oft nicht möglich ist, mit anderen Einrichtungen
zusammenzuarbeiten oder KI-Systeme mit einer zentralen Serverinstanz für ihre Zwecke einzusetzen,
da eine derartige Zusammenarbeit des Öfteren das Offenlegen interner Informationen erfordert.

Durch das Vermeiden einer zentralen Server-Instanz ist das FL-System auch robuster gegenüber
Ausfällen. So hat es keine allzu große Auswirkung, falls einzelne Clients im System ausfallen und es ist
zudem keine ständige, stabile Verbindung zum zentralen Server nötig. Auch wird das Training der
Daten auf viele kleine Bestandteile aufgeteilt und es können Clients schon mit geringen Hardware-
Anforderungen gute Modell-Ergebnisse erzielen.

# 2.1.2.1 Federated Learning und Datenschutz

Wie bereits im Unterpunkt Vorteile und Möglichkeiten von Federated Learning angedeutet, hat vor
allem das Federated Learning die Eigenschaft, im Hinblick auf rechtliche Einschränkung der EU in Form
der DSGVO [15], die Regelungen dieser Datenschutzgrundverordnung unter Umständen einhalten zu
können.

Die DSGVO wird dann angewandt, wenn jegliche Form der Verarbeitung von personenbezogenen
Daten auftritt. Dabei sind nach Artikel 4 Abschnitt 1 DSGVO personenbezogene Daten, Daten welche
sich auf „eine identifizierte oder identifizierbare natürliche Person (im Folgenden „betroffene Person“)
beziehen“ [15, S. 33 ]. Es ist innerhalb vieler KI-Systeme jedoch nicht möglich, Daten ausreichend zu
anonymisieren, um die DSGVO zu umgehen, ohne die Performance des KI-Systems stark
einzuschränken.

## Medizin-, Finanz- und Militäreinrichtungen haben, wie bereits erwähnt, zudem nicht immer die

Möglichkeit eine ausreichende Menge an Daten in ihrem Umfeld zu sammeln und versuchen vor allem
den Zugriff auf ihre Daten durch externe Dritte aus Gründen der allgemeinen Sicherheit, Privatsphäre
von Patient*innen oder zur Wahrung von Geschäftsgeheimnissen zu vermeiden. Dies bedeutet, dass
der Zukauf externer Daten für die Erweiterung des Trainingsdatensatzes oftmals ebenfalls keine
Alternative darstellt und zudem kostenintensiv ist.


Jedoch würden vor allem medizinische Einrichtungen stark von einer großen Datenmenge profitieren,
umso mehr Daten für ihre Modelle und Systeme verwendet werden und profieren parallel von einem
erhöhten Datenschutz [14].

Darüber hinaus müssen nach Artikel 5 Absatz 1 Buchstabe f DSGVO [15] personenbezogene Daten
ausreichend gesichert werden. Je sensitiver die Daten sind, desto kritischer wird deren Verarbeitung
von der DSGVO angeordnet (Artikel 9 DSGVO). Diese Verantwortlichkeit und die Sicherung der Daten
können von einigen Einrichtungen aus Kostengründen oder wegen des angesprochenen Aspekts der
Sicherheit ebenfalls nicht an Dritte übertragen werden.

Daher müssen für derartige Herausforderungen Lösungen geschaffen werden, wobei Federated
Learning eine dieser Lösungen darstellen könnte, rechtlichen Problemen hinsichtlich Datenschutzes,
Urheberschutz und dem Schutz von Geschäftsgeheimnissen entgegenzukommen. Jedoch birgt das
Verwenden einer FL-Architektur neben den genannten Vorteilen wiederum andere Gefahren und
Risiken.

#### 2.1.3 Nachteile und Herausforderungen von Federated Learning...................................................

In einem dezentralen System, in welchem die Aufgaben bzw. Trainings verteilt werden, gibt es neben
vielen Vorteilen des Federated Learning auch einige negative Aspekte und Herausforderungen. So sind
derartige Systeme besonders anfällig für bestimmte Cyberattacken. Spezifische Angriffe auf KI-
Modelle und Federated Learning werden im Abschnitt Cyberattacken auf Künstliche Intelligenz und im
Unterpunkt Cyberattacken auf Federated Learning näher ausgeführt.

Eine große Herausforderung innerhalb eines FL-Systems ist vor allem die Kommunikation zwischen
den Akteuren. In solch einem Systemen besteht eine hohe Frequenz an Anfragen und zu
übermittelnden Daten (Modellgewichte etc.). Dies kann zu Fehlern oder auch zu Überlastungen des
Netzwerks führen [12]. Dies bietet auch eine Möglichkeit für einen potenziellen Angreifer, eine DOS-
Attacke auf ein FL-System durchzuführen, um dieses zum Stoppen zu bringen (vgl. Denial of Service
Attacks in Federated Learning).

Ein weiterer Punkt ist die Daten-Heterogenität. Heterogenität beschreibt primär eine unterschiedliche
Datenqualität und Verteilung. Es ist essenziell für ein KI-Modell, heterogene Daten als Trainingsdaten
zu verwenden, um eine vorhersagbare und ausreichende Model-Performance zu erreichen. Mittels
des bereits angedeuteten Federated Averaging Algorithmus gibt es bereits Ansätze, derartige
Heterogenität herzustellen, jedoch ist dies noch nicht vollständig optimiert [12].

Zudem ist durch die Ausführung des Modells mit den Daten des Clients auf dessen Gerät der Zugriff
und die Kontrolle durch den zentralen Server erheblich eingeschränkt, was zu verschiedenen
Möglichkeiten an Cyberangriffen auf das FL-System führen kann.


## 3 Cyberattacken auf Künstliche Intelligenz

Bevor im Spezifischen auf Angriffe von FL-Systemen eingegangen wird, ist es wichtig, vorab die
einzelnen Themengebiete der Cyberattacken auf allgemeine KI-Systeme darzustellen, um ein
Verständnis der Bedrohung und damit verbundenen Herausforderungen herzustellen.

#### 3.1 Adversarial Attack

Daten bzw. Trainingsdaten sind ein zentraler Baustein bei der Erstellung von KI-Systemen. Werden
diese Trainingsdaten jedoch Ziel eines Angriffs, so nennt man dies eine Adversarial Attack [16]. Näher
beschreibt eine Adversarial Attack, das Manipulieren von Input-Daten (Bilder, Text etc.), wobei es
dann das entsprechende Ziel des Angreifers ist, dass das Zielsystem falsche Aussagen in Bezug auf
seine Vorhersage trifft. Die Adversarial Attack bzw. das Manipulieren der Daten unterteilt sich noch
einmal in die Evasion Attack und Poisoning Attack. Bei der Evasion Attack werden kleine, gezielte
Veränderungen an den Eingabedaten vorgenommen, um das Modell zu täuschen. Beispielsweise kann
ein Bild minimal verändert werden, sodass ein Bildklassifikationsmodell es falsch klassifiziert (vgl.
Abb.4). Bei der Poisoning Attack fügen Angreifer während des Trainingsprozesses manipulierte Daten
ein, um das Modell so zu trainieren, dass es falsche Vorhersagen macht. Die Evasion Attack wird hier
nicht weiter vertieft, da vor allem Poisoning Attacks bei FL-Systemen Anwendung finden und der
Fokus daher auf diese Art von Angriffen gelegt wird.

Man unterscheidet darüber hinausgehend zwischen einem White-Box-Szenario, in dem der Angreifer
vollständigen Zugriff auf das Modell und die Parameter hat und einem Black-Box-Szenario, bei
welchem der Angreifer nur die Ausgabe des Zielsystems beobachten kann.

```
Abbildung 4 : Die obere Abbildung zeigt eine Adversarial Attack. Das auf der linken Seite dargestellte Bild zeigt einen Panda,
welcher mit dem Label "Panda" versehen ist. Das Modell klassifiziert das Bild mit einer Wahrscheinlichkeit von 57,7 % als
Panda. Anschließend wird dem Bild Rauschen hinzugefügt, welches mit bloßem Auge nicht erkennbar ist. Dies führt zu einer
Beeinträchtigung der Performance des Modells, sodass bei dem gleichen Bild in der Folge mit einer Wahrscheinlichkeit von
99,3 % ein Gibbon erkannt wird [16].
```

#### 3.2 Data Poisoning

Innerhalb des Data Poisoning [17] ist es das Ziel, die Trainingsdaten eines Modells derart zu
manipulieren (zu vergiften), dass diese eine Auswirkung auf das eigentliche Training des KI-Modells
haben. Das Data Poisoning ist schwer aufzudecken, da bei dem Training von KI-Modellen viele Daten
verwendet werden, die nur schwer auf Fehler oder Manipulationen zu überprüfen sind.

Oft kann man mit dem bloßen Auge z. B. eine Bildmanipulation nur schwer erkennen (siehe Abb. 4).
Zwar gibt es immer mehr Verteidigungsmechanismen, um derartige Angriffe aufzudecken, doch wird
dies bei der Zunahme von Large-Language Modellen und ähnlichen Systemen immer schwieriger, da
auch die Datenmenge immer weiter zunimmt.

Das Data Poisoning unterteilt sich in Targeted Poisoning [18], wobei dieser Angriff auf bestimmte
Eingaben abzielt, um sicherzustellen, dass das Modell für diese spezifischen Fälle falsche Vorhersagen
trifft und Indiscriminate Poisoning [19]. Dieser Angriff zielt darauf ab, die allgemeine Genauigkeit und
Leistungsfähigkeit des Modells zu verschlechtern.

#### 3.3 Label Flipping Attack

Eine zentrale Angriffsmethode des Data Poisoning ist die Label Flipping Attack, welche auch später
innerhalb der Testdurchführung eine zentrale Rolle spielen wird (vgl. Einführung und Ziel der
Testdurchführungen).

Diese Art des Angriffs [20] ist relativ einfach durchzuführen. Dabei werden die Labels der Daten des
verwendeten Datensatzes einfach geflippt bzw. getauscht. Später wird dieser Vorgang anhand des
MNIST-Datensatzes näher erläutert (vgl. Durchführung der Label Flipping Attack am Datensatz).

In dem hier vorliegenden Datensatz CIFAR- 10 [21] (siehe Abb. 6) gibt es eine Vielzahl an Bildern, die
verschiedenen Klassen zugeordnet wurden. Diese Klassen sind unter anderem Schiffe und Flugzeuge.
Das bedeutet, dass zu jedem Bild, auf welchem ein Schiff dargestellt ist, auch ein Label mit der
Bezeichnung _Schiff_ existiert. Dies bezieht sich auch auf die Bilder, auf denen Flugzeuge dargestellt
wurden, wobei diese dann als _Flugzeug_ gelabelt sind.

Im Zuge einer Label Flipping Attack werden die Bilder, auf welchem ein Schiff dargestellt wird, jedoch
(zu Teilen) als Flugzeug gelabelt und umgekehrt (siehe Abb. 6 ). Dies bedeutet, dass das Modell
innerhalb des Trainings so ein falsches Muster erlernt und dementsprechend inkorrekte Aussagen in
Zukunft treffen wird.

```
Abbildung 5 : Der Einsatz einer SVM (Support Vector Machine) zielt darauf ab, eine
Trennlinie zwischen sich unterscheidenden Datenpunkten zu definieren (vgl. Nr. 1). Eine
Verschiebung der Datenpunktkoordinaten kann beispielsweise durch Data Poisoning
erfolgen und hat einen maßgeblichen Einfluss auf die Verschiebung der Trennlinie (vgl.
Nr. 2) sowie die Klassifizierung zukünftiger Datenpunkte [17].
```

#### 3.4 Backdoor Attack

Im Gegenzug zu einer Data Poisoning Attack, geht eine Backdoor Attack bei der Manipulation des
Modells anders vor. Dabei wird nach Definition des Papers „Neural Cleanse: Identifying and Mitigating
Backdoor Attacks in Neural Networks“ [22] eine Backdoor so beschrieben, dass ein bestimmtes
unbemerktes Muster im Training des Modells heimlich mitimplementiert wird. Dieses Muster führt zu
einem unkontrollierten Handeln des Modells, aber erst, wenn ein vorher festgelegter Trigger
ausgeführt wurde.

Im Paper „Physical Backdoor Attacks to Lane Detection Systems in Autonomous Driving“ [23] gibt es
hierfür ein praktisches Beispiel aus dem Bereich des autonomen Fahrens. Dabei wurde ein Fahrzeug
mit diversen Geräten ausgestattet, welche die unmittelbare Umgebung des Fahrzeugs überprüfen und
messen. Die Aufgabe des Modells war es, das Fahrzeug einer Straße anhand der Straßenmarkierungen
folgen zu lassen. Jedoch wurde das Modell mit einer Backdoor manipuliert. Dabei wurde die Daten
derart manipuliert, dass sobald die Geräte einen Straßenkegel erfassen, das Fahrzeug nicht dem
Straßenverlauf der Straßenmarkierung folgt, sondern nach links abbiegt (siehe Abb. 7 ).

Aufgrund dieses Beispiels ist ersichtlich, ähnlich den Data Poisoning Attacks, wie schwer
Manipulationen von Daten und Modellen rückwirkend aufzudecken sind, da man vorher keine
Kenntnis darüber hat, was einen möglichen implementierten Trigger darstellt, bis dieser ausgelöst
wird.

```
Abbildung 6 : Die nachfolgende Abbildung zeigt eine vermeintliche Label-Flipping-
Attacke in einer abstrahierten Darstellung. Auf der linken Seite sind die korrekten Daten
mit den korrekten Labels abgebildet, während auf der rechten Seite die geflippten
Labels von Schiff und Flugzeug dargestellt sind. [Quelle: Eigene Darstellung].
```
```
Abbildung 7 : Die Abbildung zeigt die zeitliche Einordnung der Implementierung des Triggers (Verkehrshütchen)
in den Datensatz. Im Anschluss erfolgt das Training des Modells unter Einbezug der zuvor genannten, potenziell
verfälschten Daten. Das Resultat ist auf der rechten Seite dargestellt. Das Fahrzeug sollte an der markierten
Stelle nach links fahren, jedoch führt der Trigger dazu, dass es nach rechts abbiegt [23].
```

#### 3.5 Fidelity Extraction Attack

In der Fidelity Extraction Attack [24] soll das Verhalten eines KI-Modells nachgebildet werden, ohne
dass der Angreifer eine Einsicht in das Modell und dessen Parameter hat. Dabei stellt der Angreifer z.
B. einem Chatbot, welcher auf dem Zielmodell basiert, spezifische Fragen, um nähere Details über das
KI-Modell zu erfahren. Der Zweck dieses Angriffs ist vor allem das Nachahmen von (meist kommerziell
erfolgreichen) Modellen und diese unter falschen Namen ebenfalls auf den Markt zu bringen. Solche
nachgebildeten Modelle können auch beim Anwender eingesetzt werden, um Vertrauen in die
Aussagekraft zu erwecken, wobei verschiedene Backdoors in das Modell eingebaut wurden, die den
Output für den Anwender unbemerkt manipulieren.

#### 3.6 Accuracy Extraction Attack

Bei folgendem Angriff versucht der Angreifer Informationen wie Genauigkeit und andere Parameter
über das Modell zu extrahieren, ohne direkten Zugriff auf das Modell zu haben [24]. Es wird versucht
z. B. die Genauigkeit des Modells oder dessen allgemeine Performance anschließend nachzubilden. Im
Vergleich zur Fidelity Attack (siehe oben) ist es das Ziel, durch das Extrahieren derartiger
Informationen, Rückschlüsse auf die verwendeten Daten im Training zu ziehen, was z. B. in Bezug auf
das Federated Learning, in welchem die zugrundeliegenden Daten verdeckt bleiben sollen, zu einem
großen Risiko werden kann.

#### 3.7 Model Extraction Attack

Der Unterschied zur Fidelity Extraction Attack [24], bei der das Verhalten eines Modells kopiert
werden soll und der Accuracy Extraction Attack, bei der auf der Grundlage des Modell-Outputs auf
dessen Trainingsdaten rückgeschlossen werden soll, geht es bei Model Extraction Attack darum das
eigentliche verwendete Modell zu replizieren. So können alle beschriebenen Angriffsmethoden auch
kombiniert werden und beeinflussen sich in ihren Ergebnissen gegenseitig. In der Regel ist es immer
ein Risiko für ein KI-System, wenn ein Angreifer über viele Informationen eines Modells, die Parameter
oder die zugrundeliegenden Daten verfügt. So sollten auch hier immer Maßnahmen getroffen werden,
um die Einsicht von Informationen auf ein Minimum zu reduzieren, wobei defensive Maßnahmen,
welche sich auf das Prinzip Security by Obscurity stützen, in der Regel nicht zu empfehlen sind.
Security by Obscurity ist ein Sicherheitsansatz, der darauf beruht, Systeme und ihre Schwachstellen
durch Geheimhaltung, statt durch robuste Sicherheitsmaßnahmen zu schützen [25].

#### 3.8 Man-in-the-middle Attack

Manipulator-in-the-middle Attack (MITM) ist eine sehr bekannte und verbreitete Angriffsform [26].
Dabei geht es darum, dass sich zwischen der Kommunikation zweier Parteien eine dritte Partei
schaltet und diverse Aktionen ausführt. Diese Aktionen können beispielsweise das Abhören der
ausgetauschten Daten sein, das Manipulieren der Daten oder die Dritte Partei gibt sich vermeintlich
als diejenige Partei aus, mit welcher ursprünglich kommuniziert werden soll.

So können die übertragenen Daten im FL-System von Akteur zu Akteur ebenfalls gestört und
manipuliert werden. Durch das Verwenden von kryptografischen Funktionen (vgl. Topologie und
Struktur - Proof of Concept), kann man diesem Angriff jedoch entgegenwirken.


## 4 Cyberattacken auf Federated Learning

Nach einer Ausführung der allgemeinen Angriffsmethoden, welche bei KI-Systemen angewandt
werden können, wird im folgenden Abschnitt spezifisch auf Angriffsmethoden auf FL-Systeme
eingegangen.

#### 4.1 Data Poisoning Attack in Federated Learning

Data Poisoning ist, wie bereits erwähnt, innerhalb der Entwicklung von KI-Systemen eine der größten
defensiven Herausforderungen. In Hinblick auf ein FL-System erweitert sich die Problematik noch um
einen weiteren Umstand, da die Daten auf dem Gerät des Clients vorliegen und sich so jedem Zugriff
eines Programms entziehen [12]. Das bedeutet, dass keinerlei Kontrolle darüber existiert, auf welchen
Daten der Client letztendlich trainiert. So kann gezielt ein Client in das System eingeschleust werden,
welcher konträre Aussagen zu den anderen Clients trifft und so das globale Modell beeinflusst.

#### 4.2 Backdoor Attacks in Federated Learning

Die Implementierung einer Backdoor in ein FL-System erfolgt nach einem ähnlichen Prinzip wie bei
einem herkömmlichen KI-System [27]. Da der Zugriff auf ein FL-System durch eine zentrale Instanz
beschränkt ist, stellt es jedoch ein noch attraktiveres Ziel für einen Angreifer dar, eine Backdoor in das
System bzw. in seine Daten einzubauen.

Zum Verständnis wird ein Szenario aufgezeigt, in welchem mehrere Krankenhäuser in einem FL-
System zusammen ein globales Modell für die Brustkrebserkennung trainieren (ähnlich dem Szenario,
welches im Abschnitt Beispielszenario medizinische Einrichtung vorgestellt wird).

Unter den registrierten Krankenhäusern befindet sich eine Einrichtung, in welcher ein IT-Mitarbeiter,
der kurz vor seiner Entlassung steht, Zugriff auf die Daten in diesem Krankenhaus besitzt. Da er vor
seinem Ausscheiden dem Krankenhaus schaden möchte, manipuliert dieser Mitarbeiter eine Anzahl
von Bildern auf denen Brustkrebs oder kein Brustkrebs dargestellt wird. Diesen Bildern fügt er nun
einen Trigger (z. B. einen einfachen Pixelblock) hinzu, lädt die Daten in das Modell und lässt das Modell
die dementsprechenden manipulierten Muster erlernen. Sobald ein derartiger Pixelblock auf einem
Bild auftaucht, trifft das Modell aufgrund des Triggers die Aussage, dass das auf dem Bild dargestellte,
kein Brustkrebs ist.

```
Abbildung 8 : Die Abbildung veranschaulicht die
potenzielle Ausgestaltung der Teilnahme eines
vergifteten Clients innerhalb eines FL-Systems.
In der Konsequenz werden die vergifteten
Daten durch den Client an den Aggregate-
Server übermittelt, was eine Vergiftung der
Leistung anderer Clients im System zur Folge
hat [Quelle: Eigene Darstellung].
```

##### 13

Das Modell teilt seine Ergebnisse mit den Ergebnissen der anderen Clients (Krankenhäuser) und kann
so unvorhersehbare Auswirkungen auf die Performance des globalen Modells und diese anderen
Clients haben. Das bedeutet, wenn in Zukunft beim praktischen Einsatz des FL-Systems, Bilder als
Input verwendet werden, die dementsprechend mit einem Pixelblock bearbeitet wurden, das Modell
auch in den anderen Einrichtungen die Aussage treffen könnte, dass es sich nicht um Brustkrebs
handelt. Dies zeigt noch einmal die Wichtigkeit von zweiten Kontrollinstanzen (z. B. durch die zweite
Begutachtung eines Arztes), auf die man sich im Einsatz von KI verlassen sollte.

Eine zusätzliche Problematik in dem hier vorgestellten Szenario ist die Tatsache, dass der Mitarbeiter
das Krankenhaus längst verlassen haben kann, das auf einen solchen Trigger trainierte Modell diesen
Trigger aber unter Umständen nie verliert und die Manipulation der Daten erst nach längerer Zeit
entdeckt wird.

#### 4.3 Denial of Service Attacks in Federated Learning

Das Ziel dieser Attacke [28] ist es, digitale Systeme wie Netzwerke und Computeranlagen für den
Betreiber unzugänglich zu machen. Meist betrifft ein derartiger Angriff die Server eines
Unternehmens, wobei durch verschiedene Angriffsarten versucht wird, dass der Server keinerlei
Anfragen mehr erhalten bzw. verarbeiten kann oder aber komplett ausfällt.

Dies kann für Unternehmen ein hohes Risiko darstellen, da in der heutigen Zeit ein nicht
funktionierender Server oft einen monetären Verlust für diese bedeutet. Manchmal erpresst der
Angreifer Geld von dem Unternehmen, indem dieser ankündigt, dass er eine DOS-Attacke durchführt,
falls dieses nicht zahlt oder aber es geht um die Zerstörung von digitaler Infrastruktur wie z. B. Cyber
Terroristen es als Ziel verfolgen.

Dieser grundlegende Angriff ist neben Angriffen auf einen Server, aber auch auf den Bereich des
Federated Learning übertragbar, da eine zentrale Server-Instanz, also der Aggregate-Server, die
Anfragen der einzelnen Clients verarbeitet und zu teils eine stabile Kommunikation mit diesen
gewährleisten muss. Zudem besteht innerhalb von FL-Systemen eine erhöhte Frequenz an
Kommunikation zwischen den Teilnehmern. Es kann daher ein nachvollziehbares Ziel des Angreifers
sein, die zentrale Serverinstanz mit Anfragen der Clients zu fluten und zum Stillstand bzw.

#### Systemabsturz zu bringen.

```
A b b i l d u n g S E Q A b b i l d u n g \ * A R A B I C 9 : Ä h n l i c h e D
Abbildung 9 : Ähnliche Darstellung eines Angriffs auf eine FL-System wie in Abb.8. Der Angreifer
(hier auf der rechten Seite) setzt in seinen Daten einen Trigger, welchen er so unbemerkt in die
globalen Modellgewichte einschleust und in Zukunft auslösen kann [27].
```

#### 4.4 Free-rider Attack

Eine Free-rider Attack [29] verfolgt weniger den Zweck ein FL-System zu schädigen, jedoch ist es das
Ziel des Angreifers einen Client mit in das System zu schleusen, welcher an den Ergebnissen der
anderen Clients partizipiert, jedoch selbst keinen Input bzw. Beitrag für das globale Modell hinzufügt.

#### 4.5 Gradient Leakage Attack

Wie schon des Öfteren beschrieben, sind die Daten des Clients von außen in der Regel nicht
einsehbar. Jedoch werden nach abgeschlossenem lokalen Training auf der Seite des Clients dessen
Ergebnisse in Form der Gradienten bzw. Modellgewichte an den zentralen Server übermittelt. Diese
Übermittlung ist jedoch anfällig für eine Man-In-The-Middle-Attack, was bedeutet, dass die
gesendeten Daten abgefangen werden können und aufgrund der Modellgewichte bzw. Gradienten auf
die ursprünglichen Daten zurückgeschlossen werden können [30].

Generell kann jedoch ein Kommunikationsangriff auf ein FL-System ein Risiko darstellen, da hierdurch
einerseits, wie bereits erwähnt, sensible Daten abgefangen werden können, die übermittelten
Modellgewichte andererseits in ihrer Übertragung aber auch manipuliert und verändert werden
können.

Dies bedeutet, dass selbst vertrauenswürdige Clients, so wie die zentrale Server-Instanz keine
Datenkontrolle mehr haben und für deren Integrität auch nicht umfassend Sorge tragen können, da
sie nach dem Versenden der Daten keinen Zugriff mehr auf diese Daten haben und nur schwer
validieren können, ob die Daten korrekt übermittelt wurden.

Es gibt hierfür jedoch einige Möglichkeiten, über Verschlüsselung z. B. dieser Attacke
entgegenzuwirken. Ähnlich ist dies auch bei der Model Inversion Attack im Federated Learning.
Hierbei wird noch einmal zusätzlich versucht, Informationen über das verwendete Modell zu sammeln.

#### 4.6 Sybil Attacks

Eine Eigenschaft, welche ebenfalls zu einem Problem hinsichtlich der Gewährleistung von
Cybersicherheit führen kann, ist das in einem FL-System die Clients in der Regel (wie in einem
klassischen demokratischen System) einen gleich stark ausgeprägten Einfluss mit ihren Outputs auf
das globale Modell haben können. So ist es möglich für einen Angreifer, dass dieser unter der
Verwendung von Aliase mehrere von ihm kontrollierte Clients in das System implementiert und diese
mit ihren manipulierten Ergebnissen, die Model Performance kontrollieren und vertrauenswürdige
Clients ebenfalls beeinflussen [31].

Wie in der Abbildung 10 zu sehen ist hat das Einschleusen eines einzigen vergifteten Clients schon für
eine Reduzierung der Genauigkeit des Modells in seiner Accuracy, bei Durchführung einer Label
Flipping Attack (siehe Label Flipping Attack) im MNIST-Datensatz, mit Tausch der Klasse 1 und Klasse 7,
gesorgt. Bei der Attack 1 (dritte Spalte von links und fünfte Zeile von oben) ist die Genauigkeit stark
gesunken. Hat der gleiche Angreifer jedoch noch einen Zwilling des manipulierten Clients mit in das
System eingebracht, ist die Genauigkeit des Modells in dieser Klasse auf 0% gesunken (siehe Attack 2).

```
Abbildung 10 : In der Abbildung ist anhand der Spalte
Baseline das durchschnittliche Modellergebnis
aufgeführt. Bei einer Label Flipping Attack auf die
Klasse 1 (Spalte Attack 1) ist die Accuracy des Modell
bereits auf 60,7% reduziert worden. Wurde eine
Sybil-Attack durchgeführt, sank die Accuracy der
Klasse 1 (siehe Spalte Attack 2) auf 0,0% [31].
```

##### 15

Hierdurch ist noch einmal ersichtlich, welche vielen unterschiedlichen Möglichkeiten Federated
Learning es Angreifern bietet, die Ergebnisse des Systems zu manipulieren oder anderweitig zu
verändern.

#### 4.7 Defensive Schutzmaßnahmen des Proof-of-Concept

Die oben aufgeführten Angriffsmöglichkeiten sollen als Wissensgrundlage dienen, um den in dieser
Arbeit zu erstellenden PoC gezielt auf manche dieser Angriffe vorzubereiten und eine gewisse
Robustheit zu gewährleisten.

So wird eine Free-Rider Attack später durch den PoC dadurch verhindert, dass sich jeder einzelne
Client eindeutig authentifizieren muss und die Modellgewichte erst aggregiert werden, wenn alle
authentifizierten Clients ihre Ergebnisse zum Aggregate-Server gesendet haben.

Auch die einzelnen Anmeldeprozesse und festgelegten Kommunikationsprotokolle innerhalb des PoC
sorgen dafür, dass die Kommunikation auch mit auftretenden Verzögerungen und Latenzen umgehen
kann. So ist einer Überlastung des Systems durch eine DDOS-Attacke einigermaßen entgegengewirkt,
da es darüber hinaus nicht möglich ist sich mit dem zentralen Server zu verbinden, sobald alle Clients
registriert und die Prozesse in Gang gesetzt worden sind, sowie die allgemeine Anzahl der Clients in
einem System aufgrund der Performance vorrangig reduziert sein soll. Durch die klare
Authentifizierung der Clients ist es zudem schwerer eine Sybil-Attack durchzuführen.

Durch die Verwendung einer Blockchain innerhalb des PoC ist es erschwert worden Gradient Leakage
und MITM-Attacken durchzuführen. Jeder Teilnehmer im System kann anhand der Blockchain
jederzeit und unabhängig überprüfen, welche Daten von einem anderen Teilnehmer ursprünglich
versendet wurden und so einen Ist-Zustand mit einem Soll-Zustand abzugleichen. Darüber hinaus sind
die einzelnen Kommunikationswege mittels AES und Public-Private-Key Encryption gesichert.

Die einzelnen konkreten technischen Umsetzungen aller aufgeführten Punkte finden sich im Abschnitt
Topologie und Struktur - Proof of Concept.

_A b b i l d u n g S E Q A b b i l d u n g \ * A R A B I C 1 1 : A u f d e r l i n k e n S e i t e e i
Abbildung 11 : Auf der linken Seite ein normales FL-System, ohne Angreifer. Auf der rechten Seite eine Sybil-Attack mit zwei
Angreifern, die Bilder der Klasse 1 mit dem Label 7 versehen haben und so das globale Modell beeinflussen [31]._


## 5 Angriffssimulation auf ein Federated Learning System.......................................................................

### 5.1 Begriffe und Definitionen

Bevor auf die nähere Beschreibung des Versuchsaufbaus eingegangen werden kann, werden im
Folgenden bestimmte Begriffe und Definitionen aufgeführt, damit einzelne diese im Laufe der Arbeit
verständlich interpretiert werden können und die Testdurchführungen nachvollziehbar sind. Einige der
Begriffe und Definition sind so den angeführten Quellen entnommen, andere Bezeichnungen wurden
individuell an das System angepasst oder eigenständig entwickelt (Siehe Markierung *).

Die Metrik der Model Accuracy wird in Bezug auf das Federated Learning zur Global Model Accuracy
(vgl. Paper „Study of Attacks on Federated Learning“ [32]) umbenannt.

```
Bezeichnung Symbol/
Abkürzu
ng
```
```
Definition
```
```
Global Model Accuracy [32]
𝐺𝑀𝐴 Die Global Model Accuracy berechnet sich
nach „Study of Attacks on Federated Learning“
[32] durch den Prozentsatz der Instanzen 𝑥∈
𝐷𝑡𝑒𝑠𝑡 , bei denen das Modell 𝑀 mit den finalen
Parametern 𝜃𝑅 die Klasse 𝑐𝑖 vorhergesagt und
𝑐𝑖 das korrekte Klassenlabel von 𝑥 ist. Im
Rahmen der eigenständigen Testdurchführung
wurde das Framework Keras bzw. Tensorflow
sowie die Categorial Accuracy Metrik [33]
verwendet, welche sich zur oberen
Berechnung nicht unterscheidet.
```
```
Global Model Recall [34]
GMR Für jede Klasse 𝑐𝑖∈𝐶 ist der 𝐺𝑀𝑅 der
Prozentsatz 𝑇𝑃𝑇𝑃𝑖
𝑖+^ 𝐹𝑁𝑖
```
##### 𝑋 100%.

```
𝑇𝑃𝑖 (True Positives) ist dabei die Anzahl der
Instanzen 𝑥 aus dem Datensatz 𝐷𝑡𝑒𝑠𝑡 bei dem
das Modell 𝑀 die Klasse 𝑐𝑖 vorhersagt und es
sich tatsächlich um die Klasse 𝑐𝑖 handelt. Sowie
𝐹𝑁𝑖 (False Negatives) die Anzahl der Instanzen
𝑥 aus dem Datensatz 𝐷𝑡𝑒𝑠𝑡 ist, bei denen das
Modell 𝑀 die Klasse 𝑐𝑖 nicht vorhersagt,
obwohl es sich um die Klasse 𝑐𝑖 handelt [32].
```
```
In der Testdurchführung wird der Marco Recall
[34] wiederum mit Keras berechnet, welcher
auf dem gleichen mathematischen Prinzip
beruht. Wobei der Durchschnitt der Recalls
aller Klassen gebildet wird.
```

Global Class 1 Accuracy/
Global Class 9 Accuracy

##### 𝐺𝐶 1 𝐴/

##### 𝐺𝐶 9 𝐴

```
Der 𝐺𝑀𝐴-Berechnung erfolgt die Accuracy -
Berechnung einer einzelnen Klasse durch:
```
```
𝐴𝑐𝑐𝑢𝑟𝑎𝑐𝑦𝑐𝑖= 𝐴𝑛𝑧𝑎ℎ𝑙^ 𝑘𝑜𝑟𝑟𝑒𝑘𝑡𝐺𝑒𝑠𝑎𝑚𝑡𝑧𝑎^ 𝑣𝑜𝑟ℎℎ𝑒𝑟𝑔𝑠𝑎𝑡𝑒𝑛𝑙 𝐼𝑛𝑠𝑡𝑎𝑛𝑧𝑒𝑛^ 𝐼𝑛𝑠𝑡𝑎𝑛𝑧𝑒𝑛 𝑣𝑜𝑛 𝑐𝑖^ 𝑥^ 𝑣𝑜𝑛^ 𝑐𝑖^
```
```
Dies wurde anhand des Frameworks Scikit-
learn und dessen Classification Report
berechnet [35].
```
Global Class 1 Recall/
Global Class 9 Recall

##### 𝐺𝐶 1 𝑅/

##### 𝐺𝐶 9 𝑅

```
Die Berechnung des Recalls [34] einer
einzelnen Klasse (hier als Beispiel Klasse 1 des
MNIST-Datensatzes) erfolgt gemäß der
Beschreibung von 𝐺𝑀𝑅 wie folgt:
```
𝐺𝐶 1 𝑅 = (^) 𝑇𝑃𝑇𝑃^1
1 +^ 𝐹𝑁 1

##### 𝑋 100%

```
Dabei wird im Anschluss jedoch nicht der
Recall-Durchschnitt aller Klassen gebildet.
```
Overfitting [36] Das Problem der Überanpassung (Overfitting)
stellt eine wesentliche Herausforderung im
Bereich des überwachten maschinellen
Lernens (ML) und des Deep Learning (DL) dar.
Es verhindert, dass Modelle sowohl die
beobachteten Daten im Trainingsdatensatz als
auch die bislang nicht betrachteten Daten im
Testdatensatz in allgemeingültiger Weise
verallgemeinern. Überanpassung tritt aufgrund
des Vorhandenseins von Rauschen, der
begrenzten Größe des Trainingssatzes und der
Komplexität der Klassifikatoren auf.
Underfitting [37]
Wenn ein maschinelles Lernmodell auf einer
begrenzten Anzahl von Datensätzen und/oder
Merkmalen trainiert wird, arbeitet das Modell
nicht effizient und erzeugt falsche Ergebnisse.
Dies wird als Unteranpassung (Underfitting)
bezeichnet. Der Hauptgrund für
Unteranpassung ist eine niedrige Varianz und
eine hohe Verzerrung (Bias) im Modelltraining.
Unteranpassung tritt auf, wenn das Modell
nicht genügend aus den Daten lernt. Wenn die
Genauigkeit der Trainingsdaten sehr niedrig
ist, ist auch die Genauigkeit der Testdaten
i.d.R. niedrig.


Poisoning Rate [32] 𝑃𝑅 Anzahl der vergifteten bzw. manipulierten
Clients in Relation zur Gesamtanzahl von
Clients 𝐾 im System:

##### 𝑃𝑅=

##### 𝑚𝑎𝑙

##### 𝐾

Anzahl vergiftete Clients* 𝑚𝑎𝑙 Anzahl vergifteter Clients 𝑚𝑎𝑙 zu Clientanzahl
𝐾 im System.

Attack Timing [32] In einem FL- System kann es jederzeit zu einem
Angriff kommen. Jedoch kann der Zeitpunkt,
wann ein Angriff stattfindet, durchaus
entscheidend in Bezug auf seine Auswirkung
sein. Wie in dem Paper „Study of Attacks on
Federated Learning“ [32] noch zu sehen sein
wird, hat ein frühzeitiger Angriff eine höhere
Auswirkung auf das vorliegende ML/DL-Modell
als ein späterer Angriff.
Clientanzahl [32] 𝐾 Anzahl der Clients im FL-System.

(System-) Runden [32] 𝑟 Anzahl an Runden/Iterationen im FL-System.

Clients pro Runde [32] 𝑐𝑝𝑟 Anzahl der Clients, dessen Modellgewichte
zufällig pro Runde aggregiert werden.

Epochen [38] 𝑒𝑛 In Machine Learning bezeichnet eine Epoche
eine vollständige Durchlaufphase des
gesamten Trainingsdatensatzes unter
Anwendung des ML/DL-Modells.


```
Modellgewichte [39] In Bezug auf das Deep Learning sind
Modellgewichte die Parameter, die während
des Trainingsprozesses angepasst werden, um
die Vorhersagen des Modells zu optimieren.
Korrekte Muster werden durch die
Gewichtung vom Algorithmus im Training
verstärkt erlernt.
Test – und Trainingsdatensatz [40]
𝑋_𝑡𝑟𝑎𝑖𝑛,
𝑦_𝑡𝑟𝑎𝑖𝑛,
𝑋_𝑡𝑒𝑠𝑡,
𝑦_𝑡𝑒𝑠𝑡
```
```
Das übliche Vorgehen vor dem ML/DL-Training
ist das Aufteilen des Datensatzes in einen
Trainingsdatensatz (X) und einen Testdatensatz
(y). Mittels des Trainingsdatensatzes wird das
Modell trainiert, während der Testdatensatz
anschließend dazu verwendet wird, den
Trainingsprozess des Modells zu validieren und
eventuell auf Over -und Underfitting zu
überprüfen.
Batch Size [41]
𝑏𝑠 Anzahl der Samples pro Gradienten
Aktualisierung. Die Gradienten-Aktualisierung
ist die Anpassung der Modellparameter
während des Trainings.
Loss [42]
Die Metrik "Loss“ beschreibt eine quantitative
Maßzahl, die den Unterschied zwischen den
vorhergesagten Ausgaben eines Modells und
den tatsächlichen Zielwerten angibt. Der Loss
dient als Grundlage für die Optimierung des
Modells während des Trainingsprozesses. Ein
geringer Loss-Wert zeigt an, dass das Modell
gut an die Daten angepasst ist, während ein
hoher Loss-Wert auf eine schlechte Anpassung
hinweist.
```
## 6 Einführung und Ziel der Testdurchführungen

Paper Code: https://github.com/michaelTJC96/Label_Flipping_Attack [32]

Eigener Code:
https://colab.research.google.com/drive/1RdvCRe_TH0mvwO9tJOPfLAEsORNgddIy?usp=sharing

Der nachfolgende Versuchsaufbau basiert auf dem Ansatz und Code des Papers „Study of Attacks on
Federated Learning“ nach T. J. Cheng [32].

Das Ziel besteht darin, vor der Entwicklung eines Proof of Concept einen Einblick in den Ablauf eines
Angriffs auf ein Federated Learning System zu erlangen. Dazu zählt die Ermittlung der erforderlichen
Zeit des Angriffs sowie die Identifikation potenzieller Einflussfaktoren auf das System, darunter die
Anzahl der Clients, die Angriffsmethode und weitere systeminterne Parameter. Die Beantwortung
dieser Versuchsfragen erlaubt eine gezielte und effiziente Umsetzung von Maßnahmen zur Abwehr
von Schwachstellen innerhalb des PoC.


Der Inhalt dieser Sektion geht vorab auf die Erkenntnisse und Ergebnisse des vorliegenden Papers ein
und wird dann durch eine Durchführung und Anpassung des Experiments auf die Umstände des
späteren PoCs eigenständig fortgeführt. Das bedeutet, dass das vorliegende Paper als Grundlage für
das ausgewählte KI-Modell, sowie die Art der Durchführung des Angriffs und die Datengrundlage
dient.

Die eigenständig durchgeführten Tests werden wiederum als Grundlage verwendet, um zu
untersuchen welche Modell-Performances das System ohne den PoC erreicht (vgl. Finale Erkenntnisse
aus den Testdurchläufen zur Ermittlung des Basis Set-Up) und welche Verbesserungen oder
Verschlechterungen die Modell-Performance mit dem PoC erreicht (vgl. Ergebnisse und Resultate des
Proof-of-Concept).

Es wurden vorab Versuchsfragen formuliert, die im Zuge der folgenden Ausarbeitung und
Auseinandersetzung getestet werden sollen, um für die verschiedenen Fragestellungen einen
Näherungswert als Antwort zu erhalten. Diese Näherungswerte bzw. Metriken werden in Begriffe und
Definitionen definiert. Durch das Verstehen derartiger Fragen können die defensiven Maßnahmen des
PoC besser entwickelt werden.

Versuchsfragen

_1. Wie viele vergiftete Clients innerhalb eines FL-Systems müssen in Relation zu nicht vergifteten_
    _Clients auftreten, dass diese eine messbare Auswirkung auf das Endresultat haben?_
    _Dabei bezieht sich das Endresultat auf die Validierungsparameter Global Model Accuracy,_
    _Global Class Recall, Global Class 1 Accuracy, Global Class 9 Accuracy, Global Class 1 Recall und_
    _Global Class 9 Recall.
2. Welche Auswirkungen hat die Steigerung der Poisoning Rate auf das FL-System?
3. Wie anfällig ist der MNIST-Datensatz gegenüber einer Label Flipping Attack?
4. Wie verhält sich das verwendete DL-Modell bei einer Label Flipping Attack?
5. Gibt es Differenzen der Performance bzw. Validierungsparameter zwischen der Label Flipping_
    _Attack, welche Klasse 1 und 9 oder 3 und 8 vertauscht?
6. Sind Non-IID Daten im Vergleich zu normalen (nicht Non-IID) Daten anfälliger für eine Label_
    _Flipping Attack (vgl. Daten, Preprocessing und Non-IID)?
7. Welche Kombination der Parameter (Clientanzahl, Epochenanzahl, Clients pro Runde, Batch_
    _Size) führt zur Stabilität gegenüber einer Label Flipping Attack bzw. welcher spezifische_
    _Parameter hat auf die Stabilität den größten Einfluss?_

Ein konkretes Ziel der eigenständigen Testdurchführung ist es später für den PoC eine
Grundeinstellung an Parametern (Clientanzahl, Epochenanzahl, Clients pro Runde, Batch Size usw.)
unter der Verwendung des MNIST-Datensatzes zu erstellen, welche möglichst robust gegenüber einer
Label Flipping Attack ist. Zudem ist es wichtig, eine annähernde Vergleichbarkeit zwischen den Tests
herzustellen, um die einzelnen Versuchsfragen anhand der gleichen Parametereinstellung bei
möglichst allen Testläufen zu überprüfen.

_Disclaimer_
Das Testen von Federated Learning Systemen und der Vergleich ihrer Ergebnisse unter verschiedenen
Bedingungen, kann eine Herausforderung darstellen, da die Komplexität und die Variabilität der
beteiligten Faktoren es schwierig machen, konsistente und vergleichbare Ergebnisse zu erzielen.


In dem vorliegenden System werden die Daten zufällig verteilt und können das Ergebnis stark
verzerren. Zum Beispiel werden in einer Testrunde viele Samples einer bestimmten Klasse mit in das
Training übernommen und in einer anderen Runde kaum. Auch wird bei der Testdurchführung anhand
eines oder mehrerer vergifteter Clients in manchen Runden der vergiftete Client miteinbezogen und in
manchen Runden nicht. Dies ist alles zufallsgesteuert, um so auch ein realistisches Abbild späterer
Einsatzszenarien wiederzugeben.

Auch die Netzwerkbedingungen, wie Latenz und Bandbreite, können stark schwanken und somit die
Synchronisation und Kommunikation zwischen den Geräten beeinflussen, was die Ergebnisse
erheblich verfälschen kann. Die Testdurchführungen wurden zuteilen an unterschiedlichen Geräten,
mit unterschiedlicher Hardware und Entwicklungsumgebung durchgeführt. Die einzelnen
verwendeten Hardware-Komponenten sind vor jeder Testdurchführung mit aufgelistet. Es kann jedoch
nicht ausgeschlossen werden, dass das Trainieren eines Modells anhand einer GPU unter Umständen
ein anderes Modell-Performance Ergebnis erzielt hat als das Training unter der Verwendung einer
CPU.

Jegliche Ergebnisse und Vergleiche sollten daher mit Vorsicht interpretiert und im Kontext der
spezifischen Testbedingungen betrachtet werden.

### 6.1 Versuchsaufbau nach dem Paper

#### 6.1.1 Datensatz

Das Experiment innerhalb des Papers [32] verwendet den Bildklassifizierungsdatensatz CIFAR- 10 [21].
Der Datensatz besteht aus 60.000 Farbbildern mit der Abmessung 32x32 Pixel in einer Ausprägung von
insgesamt zehn unterschiedlichen Klassen – Flugzeug, Automobil, Vogel, Katze, Hirsch, Hund, Frosch,
Pferd, Schiff und Lastwagen. Jede Klasse umfasst dementsprechend 6.000 Bilder.

Der vollständige Datensatz ist vorab in fünf Trainingsbatches und einen Testbatch (vgl. Begriffe und
Definitionen) unterteilt, jeder mit 10.000 Bildern. Der Datensatz ist demnach auf 50.000
Trainingsbilder (X_train=50.0000) und 10.000 Testbilder (y_test=10.000) aufgeteilt.

#### 6.1.2 Ziel des Angreifers

Im vorliegenden Experiment ist es das Ziel des Angreifers, dass nicht wahllos Klassen des CIFAR- 10
Datensatzes vergiftet werden, sondern gezielt einzelne Klassen Ziel des Angriffs sind. Dies dient dazu,
dass der Angriff so in der Regel schwerer aufzudecken ist [32]. Das Ziel besteht darin, die allgemeine
Modell-Performance des globalen Modells zu reduzieren. Der Angreifer hat jedoch auch bestimmte
Einschränkungen, um einen realen Angriff durchzuführen.

So kann jeder bösartige Teilnehmer nur die Trainingsdaten auf seinem eigenen Gerät manipulieren
und nicht die Daten anderer Teilnehmer im System. Kein bösartiger Teilnehmer kann auf den Modell-
Lernprozess zugreifen, sowie auf das lokale Training der einzelnen Clients. Zudem kann kein bösartiger
Teilnehmer den Aggregations-Algorithmus kontrollieren, der verwendet wird, um die Aktualisierungen
aller Teilnehmer in das gemeinsame Modell zu kombinieren.

#### 6.1.3 Angriffsmethode Label Flipping

Die Label Flipping Attack ist, wie bereits in Punkt Label Flipping Attack beschrieben, eine der
verbreitetsten und effizientesten Angriffsmethoden auf ein FL-System [20]. Dabei ist es konkret das
Ziel, das Label, also eine der zehn Klassen des CIFAR-10 Datensatzes, auszutauschen (zu flippen),
wodurch das Modell auf ein fehlerhaftes Muster konditioniert wird und inkorrekte Aussagen treffen
soll.


Konkret bedeutet das in diesem Fall, dass die Klasse 1 (Flugzeug) mit der Klasse 9 (Schiff) vertauscht
wird. Das Modell lernt dementsprechend zum Begriff Flugzeug anhand der Bilder von Schiffen,
während wiederum das Modell beim Begriff Schiff mit den Bildern von Flugzeugen lernt.

In einem FL-System, in welchem eine Vielzahl von unterschiedlichen Clients existieren, kann eine
manipulierter Client durch Falschaussagen auch die Entscheidungsfindung anderer Clients
beeinträchtigen. Es hängt darüber hinaus jedoch noch von mehreren Faktoren ab, inwiefern ein
Modell in einem FL-System beeinflusst werden kann.

Dabei können folgende Faktoren nach dem Artikel „Federated learning: a comprehensive review of
recent advances and applications“ nach H. Kaur et al. [43] einen Einfluss auf das Ergebnis des
verwendeten FL-Systems haben:

1. Systemheterogenität
    Die verwendeten Clients verfügen in der Regel über unterschiedliche Hardware und können so
    jeweils ihren Output beeinflussen.
2. Statistische/Daten Heterogenität
    Die unterschiedliche Verteilung von Daten über das Netzwerk kann ebenfalls einen Einfluss
    auf das Ergebnis eines FL-Systems haben.
3. Kommunikationsengpässe
    Durch die hohe Frequenz und den Austausch an Informationen kann es in der Übertragung zu
    Fehlern kommen und Daten bzw. Clients partizipieren haben so einen unterschiedlichen
    Einfluss auf das globale Modell.
4. Datenschutz
    Um zu verhindern, dass einzelne sensitive Daten der Clients veröffentlich werden, wurden
    diverse Methoden wie Secure Multi-Party Computation (SMPC) und Diferential Privacy (DP)
    entwickelt, um diesen Problemen entgegenzuwirken. Jedoch haben diese Methoden unter
    Umständen wiederum einen Einfluss auf das Ergebnis des FL-Systems.

#### 6.1.4 Resultate und Ergebnisse des Papers

6.1.4.1 Label Flipping Attack

```
Abbildung 12 : Wie in der Abbildung 13 ersichtlich, werden jeweils zwei Szenarien einer Label Flipping Attack
dargestellt. Es wurde die Klasse 1 mit der Klasse 9 (Automobil mit Schiff) und die Klasse 0 mit der Klasse 2
(Flugzeug mit Vogel) vertauscht. Die jeweilige Genauigkeit in Prozent des Modells ist auf der Y-Achse
dargestellt. Die X-Achse zeigt den Prozentsatz der vergifteten Clients (im Paper als "m %" bezeichnet).
Innerhalb der vorliegenden Untersuchung wurde eine Poisoningrate von 0 % bis 40 % berücksichtigt [32].
```

6.1.4.2 Erkenntnisse Label Flipping Attack
Im Paper „Study of Attacks on Federated Learning“ [32] wurden verschiedene Angriffsmethoden auf
das FL-System durchgeführt. Verstärkt wurde dabei jedoch auf die Label Flipping Methode
eingegangen. Dies ist der Grund, warum hier einerseits verstärkt das Ergebnis dieser Methode
interpretiert wird. Ein weiterer Grund ist jedoch, dass die Angriffsmethode des Label Flipping
technisch gut auf den PoC im späteren Verlauf übertragen werden kann und dementsprechend
nachvollziehbar ist.

Wie in der Abbildung 13 zu sehen, ist die Genauigkeit des Modells schon bei einer Poisoning Rate von
m% = 2% beeinträchtigt worden (m%=Poisoning Rate). Die Genauigkeit folgt einem abnehmenden
Trend bei einer Zunahme der Poisoning Rate. So kann das Ergebnis des Papers so interpretiert werden,
dass bei einer Zunahme der vergifteten Clients bzw. bei Steigerung der Poisoningrate m%, anhand
einer Label Flipping Attack unter Verwendung eines Multiklassen Bildklassifikation-Modells, die
prozentuale Genauigkeit des Modells in Bezug auf die Global Model Accuracy (𝐺𝑀𝐴), abnimmt.

6.1.4.3 Attack Timing mit einer Label Flipping Attack

Der Zeitpunkt bzw. das Timing, wann ein Angriff auf das globale Modell stattfindet, ist auch von
entscheidender Bedeutung [32]. So können Angreifer durch eine gute Zeitplanung auftretende
Anomalien verhindern, welche wiederum von eingesetzten Sicherungsmechanismen aufgedeckt
werden können und den richtigen unbemerkten Zeitpunkt für ihren Angriff abpassen.

_Abbildung_^13 _: In dieser Abbildung zu sehen, wurden innerhalb der ersten 105 Runden
die vergifteten Clients mit in das Training einbezogen. Hierdurch ist die Global Model
Accurarcy des vergifteten Modells im Laufe der 200 Runden im Vergleich zum nicht
vergifteten Modell um 3.27% auf insgesamt 75.34% gesunken [32]._


##### 24

6.1.4.4 Erkenntnisse Attack Timing Label Flipping Attack
Zusammengefasst sind frühe Phasen eines Poisoning-Angriffs dann effektiv, wenn der Angriff
kontinuierlich durchgeführt wird, bevor das globale Modell in einen stabilen Zustand gerät. Allerdings
besteht die Gefahr, dass das globale Modell konvergiert und die Genauigkeit zu einem Normalzustand
wiederhergestellt wird, wenn der Angriff in einer zu frühen Phase beginnt oder nicht lange genug
andauert. Es zeigt sich dennoch, dass es effektiver aus Sicht des Angreifers ist, den Angriff in den
früheren Trainingsrunden in einem FL-System durchzuführen.

### 6.2 Eigenständige Durchführung des Experiments

Alle Testergebnisse wurden unter folgendem Link als Quelle in Bildform hinterlegt:
https://drive.google.com/drive/folders/1LKf1CBEr4QLxiyjRf4oGKzZDQ65WasK7?usp=drive_link

#### 6.2.1 Einführung und Testmethodik

Da innerhalb des Papers [32] das Framework PyTorch [44] verwendet wurde und darüber hinaus der
Paper-Code schwer an die Gegebenheiten und Umstände des geplanten PoC anzupassen ist, wurde
auf Grundlage des Papers aufbauend, der Test durch eine eigenständige Testreihe erweitert.

Dabei wird jedoch dasselbe Modell (im Tensorflow-Framework), Angriffsart und Datengrundlage
(jedoch MNIST anstatt CIFAR-10) in der Testdurchführung des Papers und innerhalb der
Testdurchführung des PoC verwendet (vgl. Evaluation und Ergebnisse des Proof-of-Concept).

Die Durchführung der Testreihe ist in verschiedene Abschnitte gegliedert. Das Ziel des ersten
Abschnitts der Testdurchführung ist die Erstellung des sog. Basis Set-Up. Es wird beobachtet, welche
Auswirkung die Umstellung einzelner Parameter auf das Modell und die Daten bzw. dessen Ergebnis
haben. Das Basis Set-Up soll als eine Experiment-Grundlage dienen, die von ihren Ergebnissen nur
mäßigen Schwankungen unterliegt, sowie über eine ausreichende Anzahl an Clients verfügt und ein
realistisches Szenario in Bezug auf die Datenverteilung innerhalb der einzelnen Clients widerspiegelt.
Dies hat den Grund, dass bei einem sehr instabilen Set-Up die Testergebnisse pro durchgeführten
Testdurchlauf unter Umständen derart stark schwanken, dass die einzelnen Testdurchläufe nicht mehr
miteinander verglichen werden können.

```
A b b i l d u n g S E Q A b b i l d u n g \ * A R A B I C 1 5 : W i e i n A b b i l d u n g
```
```
Abbildung 14 : Wie in der Abbildung dargestellt, wurden die vergifteten Clients erst nach Runde 105
miteinbezogen. Es zeigt sich ein simultanes nicht so ausgeprägtes Verhalten zu Abb. 14, indem die
allgemeine Global Model Accurarcy des vergifteten Modells im Vergleich zu einem nicht vergifteten
Modell abnimmt. Der Wert sinkt um 2,41 Prozentpunkte auf 76,20 Prozent [32].
```

Das Ziel ist es demnach, eine Auswahl an Parametern für ein FL-System zu treffen, die eine möglichst
hohe Anzahl an Clients aufweist und zusätzlich eine solide und stabile Modell-Performance der
einzelnen Clients und der zentralen Serverinstanz erzielt.

Der weitere Abschnitt soll dann die Beantwortung der restlichen Versuchsfragen (vgl. Versuchsfragen)
umfassen und wird anhand der Testläufe mit Hilfe des zuvor ermittelten Basis Set-Up durchgeführt.

Die Modell-Performance Ergebnisse werden mit einem Prozentwert zwischen 0.0 und 1.0 angegeben
und sind eine äquivalente Darstellungsform von 0% bis 100%. Dabei wurden die Ergebnisse bei vier
Nachkommastellen abgeschnitten, also weder auf- noch abgerundet.

Bei der Durchführung der Testdurchgänge wird der MNIST-Datensatz in Non-IID verwendet (vgl.
Daten, Preprocessing und Non-IID). Auch das verwendete Modell wird in Erstellung des Deep Learning
Modells spezifischer beschrieben.

Es wird im Speziellen untersucht, inwiefern folgende Parameter eine Auswirkung auf die Performance
des Modells besitzen. Alle folgenden Begriffe und Validierungsparameter bzw. Metriken wurden
bereits in Abschnitt Begriffe und Definitionen näher erläutert.

Auswirkung auf die Modell-Performance durch Änderung folgender Parameter

1. Anzahl der Clients in einem FL-System (𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾)
2. Anzahl der Epochen pro Training pro Client im FL-System (𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛)
3. Anzahl der Runden innerhalb eines FL-Systems (𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟)
4. Auswirkungen der Batch-Sitze eines Client-Modells (𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠)
5. Auswirkung durch Erhöhung der Poisoning Rate (𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅)
6. Auswirkung von IID und Non-IID Daten auf das Modell
7. Anzahl der partizipierenden Clients pro Runde (𝐶𝑙𝑖𝑒𝑛𝑡𝑠 𝑝𝑟𝑜 𝑅𝑢𝑛𝑑𝑒 𝑐𝑝𝑟)

Messung der Modell-Performance anhand folgender Validierungsparameter

1. Global Model Accuracy (𝐺𝑀𝐴)
2. Global Model Recall (𝐺𝑀𝑅)
3. Global Class Accuracy Klasse 1 und 9 (𝐺𝐶 1 𝐴/𝐺𝐶 9 𝐴)
4. Global Class Recall Klasse 1 und 9 (𝐺𝐶 1 𝑅/𝐺𝐶 9 𝑅)

6.2.1.1 Ermittlung des Basis Set-Up

Der folgende Testdurchlauf umfasst den oben bereits erwähnten Abschnitt zur Ermittlung des Basis
Set-Up für die weiterführenden Tests der Versuchsfragen. Es werden wie in Tabelle u.a. 1.0 zu sehen
verschiedene Parameter ausprobiert und getestet und anhand der Testergebnisse in u.a. Tabelle 1.1
kontrolliert, inwiefern die einzelnen Anpassungen der Parameter eine Auswirkung auf die Modell-
Performance haben. Testdurchläufe mit der höchsten Modell-Performance werden zu teils grün
markiert.

_Hardware Set-Up_

Google Colab mit NVIDIA Tesla T4 GPU mit 16 GB GDDR6 Speicher und 16GB RAM.

Code: https://colab.research.google.com/drive/1RdvCRe_TH0mvwO9tJOPfLAEsORNgddIy?usp=sharing

Als erster Schritt wurde getestet, welchen Einfluss die Erhöhung der Clientanzahl auf die Modell-
Performance besitzt.


```
Testdurchlauf 1. Ermittlung Basis Set-Up (Erhöhung der Clientanzahl)
```
Durchgang Clientanzahl
𝐾

```
Epochenanzahl
𝑒𝑛
```
```
Rundenanzahl
𝑟
```
```
Anzahl
vergiftete
Clients 𝑚𝑎𝑙
```
```
Non-IID Anzahl
Clients
pro
Runde
𝑐𝑝𝑟
```
```
Batch
Size 𝑏𝑠
```
1 1 3 3 0 ja 5 4

2 3 3 3 0 ja 5 4

3 5 3 3 0 ja 5 4

4 10 3 3 0 ja 5 4

```
Tabelle 1.0
```
```
Ergebnisse Testdurchlauf 1.
```
```
Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
1 0.9901 0.9901 0. 9929 0. 9939 0. 9947 0.9831
2 0. 3725 0. 3647 0. 2037 0. 5851 0. 9207 0. 3746
3 0. 1134 0.1 0.1135 0.0 1.0 0.0
4 0. 1324 0. 1184 0.1166 0.0 1.0 0.0
Tabelle 1.1
```
```
Wie in der Tabelle 1.0 zu sehen ist die globale Model Accuracy (𝐺𝑀𝐴) zu Beginn mit 99,01% sehr
hoch, jedoch ist ab einer Clientanzahl 𝐾≥ 3 eine enorme Reduzierung der allgemeinen Performance
bzw. aller Metriken zu bemerken. Dies hatte den Umstand, dass innerhalb des Testdurchlaufs noch
nicht eingeführt wurde, dass pro Rundendurchgang nur eine bestimmte und zufällig ausgewählte
Menge an Clients partizipieren, sondern die Modellgewichte aller Clients aggregiert wurden. Durch die
Einführung, dass pro Runde immer nur unterschiedliche Clients ihre Modellgewichte zur Aggregation
bereitstellen, ist die allgemeine Modell-Performance drastisch gestiegen (zu sehen in Tabelle 1.2).
```
```
Testdurchlauf 2. Ermittlung Basis Set-Up (Erhöhung der Epochen - und Clientanzahl)
```
```
Durchgang Clientanzahl
𝐾
```
```
Epochenanzahl
𝑒𝑛
```
```
Rundenanzahl
𝑟
```
```
Anzahl
vergiftete
Clients
𝑚𝑎𝑙
```
```
Non-
IID
```
```
Clients
pro
Runde
𝑐𝑝𝑟
```
```
Batch
Size
𝑏𝑠
```
```
5 1 5 3 0 ja x 4
6 3 5 3 0 Ja 2 4
7 5 5 3 0 ja 3 4
8 10 5 3 0 ja 3 4
Tabelle 1.2
```

_Ergebnis Testdurchlauf 2._

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
5 0. 9896 0. 9895 0. 9938 0.987 0. 9903 0. 9781
6 0. 9404 0. 9393 0. 9698 0. 9731 0. 9903 0. 9326
7 0.6802 0. 6760 0. 5855 0. 8342 0. 9947 0. 4539
8 0.6755 0. 6675 0. 5236 0. 6892 0. 9955 0. 6461
Tabelle 1.3

Innerhalb des oberen Testdurchlaufs (Tabelle 1.2) sieht man im Vergleich zu Testdurchlauf in Tabelle
1.1, dass keine mehr so starke Performance-Reduzierungen innerhalb der einzelnen Testdurchläufe
auftreten, wobei dennoch zwischen Durchgang 6 und 7 ein starker Rückgang der 𝐺𝑀𝐴 zu verzeichnen
ist. Die potenzielle Erklärung für die beobachtete Abweichung könnte in der erhöhten Heterogenität
der Clientdaten liegen, wie in Abschnitt Daten, Preprocessing und Non-IID dargelegt. Die
Schwankungen dieser Daten erschweren dem globalen Modell die Generalisierung aufgrund der
einzelnen Datenpunkte. Generalisieren bedeutet, dass ein Machine Learning bzw. Deep Learning
Modell nicht nur auf den Trainingsdaten, sondern auch auf neuen, zuvor ungesehenen Daten
(Testdaten) ausreichende Leistung zeigt [45].

_Testdurchlauf 3. Ermittlung Basis Set-Up (Erhöhung der Runden - und Clientanzahl)_

```
Durchgang Clientanzahl
𝐾
```
```
Epochenanzahl
𝑒𝑛
```
```
Rundenanzahl
𝑟
```
```
Anzahl
vergiftete
Clients
𝑚𝑎𝑙
```
```
Non-
IID
```
```
Clients
pro
Runde
𝑐𝑝𝑟
```
```
Batch
Size
𝑏𝑠
```
9 1 3 5 0 ja 1 4
10 3 3 5 0 ja 2 4
11 5 3 5 0 ja 3 4
12 10 3 5 0 ja 3 4
Tabelle 1.4

_Ergebnis Testdurchlauf 3._

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
9 0.9894^ 0.9892^ 0.9912^ 0.9812^ 0.9973^ 0.9871^
10 0. 8853 0. 8847 0.6758 0. 9112 0. 9938 0.7938
11 0. 4889 0. 4778 0. 2588 0. 6666 0.9973 0. 4638
12 0. 7486 0. 7453 0. 9865 0. 8418 0. 9057 0. 8444
Tabelle 1.5

Eine allgemeine Erhöhung der Rundenanzahl 𝑟 von 3 auf 5 Runden zeigt vorerst keine großen
Unterschiede zu den Testläufen davor, jedoch ist in Durchgang 12 zu erkennen, dass Metriken im
Vergleich zu Durchgang 11 deutlich höher sind. Ggf. führt eine Erhöhung der Rundenzahl 𝑟 zu einer
höheren Performance bei einer ebenfalls erhöhten Clientanzahl 𝐾


_Testdurchlauf 4. Ermittlung Basis Set-Up (Erhöhung der Batch Size und Clientanzahl)_

```
Durchgang Clientanzahl
𝐾
```
```
Epochenanzahl
𝑒𝑛
```
```
Rundenanzahl
𝑟
```
```
Anzahl
vergiftete
Clients
𝑚𝑎𝑙
```
```
Non-
IID
```
```
Clients
pro
Runde
𝑐𝑝𝑟
```
```
Batch
Size
𝑏𝑠
```
13 1 3 3 0 ja x 32
14 3 3 3 0 Ja 2 32
15 5 3 3 0 Ja 3 32
16 10 3 3 0 ja 3 32
Tabelle 1.6

_Ergebnis Testdurchlauf 4._

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
13 0.9889 0.9888 0.9920 0.9851 0.9955 0.9831
14 0. 8346 0. 8341 0. 9824 1.0 0. 9850 0. 2021
15 0. 4805 0. 4741 0. 2870 0. 9130 0. 9991 0. 0208
16 0. 8607 0. 8598 0. 8448 0. 9501 0. 9832 0. 6045
Tabelle 1.7

Auch in der Tabelle 1.6 sieht man einen stabilen Anfang in Bezug auf die Werte mit einer Reduzierung
der Modellperformance bei der Durchführung des Testlaufs mit einer Clientanzahl von 𝐾 = 5. Die
Erhöhung der Batch Size von 𝑏𝑠 = 4 auf 𝑏𝑠 = 32 hat jedoch die 𝐺𝑀𝐴 insgesamt betrachtet, von
77,8% auf 79,1% im Durchschnitt gesteigert. Daher wird in der folgenden Testdurchführung versucht,
eine größere Batch Size als Parameter in die Testläufe mit einzubeziehen.

Individuelle Parameteranpassung auf Grundlage vorheriger Erkenntnisse

Die Annäherung anhand des Austestens der Auswirkung der Parametereinstellung auf die allgemeine
Modell-Performance hat einige Erkenntnisse geliefert, welche innerhalb der sich anschließenden
Testdurchführung näher betrachtet werden sollen.

Es hat sich gezeigt, dass der Einsatz eines einzelnen Clients durchweg die stabilsten Modell-
Performances erreicht hat. Jedoch ist die Verwendung eines einzelnen Clients innerhalb eines FL-
Systems hinfällig. Es zeichnete sich jedoch auch ab, dass die Modell-Performance nach einem
regelmäßigen Performance-Drop bei 𝐾= 5 sich mit der Zunahme der Clientanzahl 𝐾 wieder weiter
stabilisierte und stieg. Dementsprechend wird mit einer durchschnittlichen Erhöhung der Clientanzahl
𝐾≥ 5 getestet, sowie einer höheren Batch Size als die ursprünglichen 𝑏𝑠= 4. Die Anzahl der Runden
und die Erhöhung der Epochenanzahl wird ebenfalls weiterhin getestet, da diese bis zum aktuellen
Stand eine nicht allzu starke messbare Auswirkung auf die Modell-Performance ausgeübt haben.

_Testdurchlauf 5. Individuelles Fine-Tuning der Parameter_

```
Durchgang Clientanzahl
𝐾
```
```
Epochenanzahl
𝑒𝑛
```
```
Rundenanzahl
𝑟
```
```
Anzahl
vergiftete
Clients
𝑚𝑎𝑙
```
```
Non-
IID
```
```
Clients
pro
Runde
𝑐𝑝𝑟
```
```
Batch
Size
𝑏𝑠
```
```
17 10 3 5 0 ja 5 32
18 5 5 5 0 ja 3 32
19 5 5 10 0 ja 3 32
20 5 10 5 0 Ja 3 32
```

21 5 5 5 0 ja 3 16
22 7 5 5 0 ja 3 16
23 7 10 5 0 ja 3 16
24 7 5 10 0 Ja 3 16
25 7 5 5 0 Ja 3 64
26 7 5 5 0 Ja 3 16
27 7 5 5 0 ja 3 16
28 7 3 5 0 Ja 3 16
Tabelle 1.8

_Ergebnis Testdurchlauf 5._

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
17 0. 2242 0. 2131 0. 2050 0. 4576 0. 9991 0. 0267
18 0.8097 0.8103 0.9094 0.9483 0.8317 0.4915
19 0.4043 0.4093 1.0 0.7725 0.0273 0.1783
20 0.4142 0.4112 0.9962 0.6923 0.4713 0.1159
21 0.6304 0.6315 0.9956 0.7385 0.4052 0.4786
22 0.8623 0.8624 0.8708 0.988 0.9330 0.4895
23 0.8443 0.8420 0.9706 0.9891 0.9903 0.7224
24 0.7585 0.7610 0.7404 0.6617 0.6132 0.9405
25 0.4379 0.4273 0.3156 1.0 0.9973 0.0019
26 0.8122 0.8108 0.9941 0.9481 0.9022 0.7433
27 0.8273 0.8312 0.9863 0.5632 0.5101 0.9395
28 0.6546 0.6479 0.9659 0.9524 0.8757 0.5163
Tabelle 1.9

#### 6.2.3 Ermittlung des Basis Set-Up

Aus den Tabellen 1.8 und 1.9 lassen sich mehrere wichtige Erkenntnisse und Schlussfolgerungen
ableiten.

Mehr Clients führen tendenziell zu besseren Gesamtergebnissen (𝐺𝑀𝐴), wie in den Durchgängen 22,
23 und 26 mit 7 Clients und jeweils einer hohen 𝐺𝑀𝐴 zu beobachten ist (grün markiert). Eine größere
Batch Size 𝑏𝑠 (z. B. Durchgang 25 mit 64) führt jedoch nicht immer zu besseren Ergebnissen. Hier ist
die 𝐺𝑀𝐴 deutlich niedriger (0.4379) im Vergleich zu ähnlichen Durchgängen mit kleinerer Batch Size.

Mehr Epochen und Runden können zu verbesserten Genauigkeiten führen, aber es ist kein linearer
Zusammenhang erkennbar. Beispielsweise hat Durchgang 19 eine niedrigere 𝐺𝑀𝐴 (0.4043) im
Vergleich zu Durchgang 18 mit einer 𝐺𝑀𝐴 von 0.8097.

Die Anzahl der Runden scheint ebenfalls eine wichtige Rolle zu spielen, wie in Durchgang 24 mit einer
𝐺𝑀𝐴 von 0.7585 im Vergleich zu Durchgang 23 mit einer 𝐺𝑀𝐴 von 0.8443.

Es gibt erhebliche Unterschiede in der Genauigkeit zwischen den Klassen 1 und 9 in einigen
Durchgängen. Zum Beispiel hat Durchgang 25 eine hohe 𝐺𝐶𝐴 für Klasse 9 (1.0), aber wiederum eine
sehr niedrige für Klasse 1 (0.3156). Dies deutet darauf hin, dass das Modell möglicherweise besser auf
bestimmte Klassen trainiert wird, was auf eine Ungleichverteilung der Daten oder Schwierigkeiten bei
der Verarbeitung bestimmter Klassen hinweisen könnte. Inwieweit die Auswahl der Klassen einen
Unterschied in der Modellperformance ausmachen kann, wird im Testlauf Label Flipping Attack bei
Klasse 1 und 9 und 3 und 8 beschrieben.


Der Unterschied zwischen der 𝐺𝑀𝐴 und den Klassengenauigkeiten (𝐺𝐶 1 𝐴, 𝐺𝐶 9 𝐴) zeigt die
Herausforderungen für das Modell anhand der vorliegenden Daten zu trainieren. Einen Grund hierfür
könnten die Non-IID-Daten bzw. die unterschiedliche Verteilung der Daten darstellen. Beispielsweise
zeigt Durchgang 17 eine niedrige 𝐺𝑀𝐴 (0.2242), was die Varianz innerhalb der möglichen Ergebnisse
noch einmal unterstreicht.

Eine 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 7 und eine ausgewogene 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠 = 16 scheinen zu guten
Ergebnissen zu führen, wie in Durchgängen 22 und 23 zu sehen ist. Eine angemessene Anzahl von
Epochen und Runden ist wichtig, jedoch gibt es auch hier keinen klaren linearen Zusammenhang. Zu
viele Epochen oder Runden könnten zu Überanpassung bzw. Overfitting führen (vgl. Begriffe und
Definitionen). Daher wird die 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛 = 5 , als Kompromiss einer höheren Epochenzahl
gewählt, welche jedoch vor einem Overfitting schützen könnte. Auch eine 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 = 5
erscheint auf der Grundlage der Daten ein einigermaßen zufriedenstellender Kompromiss zu sein.

Womit die finalen Parameter für das Basis Set-Up der folgenden Parameter festgelegt werden:

```
● 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 7
● 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛= 5
● 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟= 5
● 𝐶𝑙𝑖𝑒𝑛𝑡𝑠 𝑝𝑟𝑜 𝑅𝑢𝑛𝑑𝑒 𝑐𝑝𝑟= 3
● 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠= 16
```
6.2.3.1 Finale Erkenntnisse aus den Testdurchläufen zur Ermittlung des Basis Set-Up
Wie in der oberen Tabelle 1.1 bzw. 1.2 für den Durchgang 1 bis 4 zu beobachten ist, gibt es eine
massive Reduzierung der 𝐺𝑀𝐴 und 𝐺𝑀𝑅 bei einer Steigerung der 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾. Um dieser
Entwicklung entgegen zukommen wurden ab Durchgang 5 zufällig Clients pro Runde zum Training
hinzugefügt und andere ausgeschlossen, um so pro Runde eine größere Varianz an Ergebnissen zu
erzielen und nicht einen Client einen zu starken Einfluss auf das globale Modell zu überlassen.

Wie man des Weiteren beobachten konnte, wurden die Ergebnisse der einzelnen Testläufe dadurch in
der Folge wesentlich stabiler, wobei dennoch innerhalb von Durchgang 5 bis 8 (Tabelle 1.2 und 1.3)
eine Reduzierung der 𝐺𝑀𝐴 und 𝐺𝐶𝐴 bei Steigerung der 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾 von 1,3,5 und 10, in
Verbindung mit einer erhöhten 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑧𝑎ℎ𝑙 𝑒𝑛 von 3 auf 5 Epochen, nachzuvollziehen ist.

Im Durchgang 9 bis 12 (Tabelle 1.4 und 1.5) wurden neben der Erhöhung der 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾 von
1,3,5 und 10 die 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 von 3 auf 5 Runden erhöht. Zu bemerken ist der Performance-Drop
bei einem Client – und Rundenanzahl von 5, wobei sich die Modellperformance bei einer Erhöhung
auf 10 Clients wiederum stabilisierte.

Auch ist im Durchgang 13 bis 16 (Tabelle 1.6 und 1.7) ein sehr ähnlicher Verlauf, mit einem
Performance-Drop bei einer 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 5 , bei Erhöhung der Batch Size von 𝑏𝑠= 4 auf 𝑏𝑠=
32 , wie beim Durchgang 9 bis 12 (Tabelle 1.4 und 1.5) zu beobachten.


Die Erkenntnisse, welche auf Grundlage der Testdurchgänge von Durchgang 1 bis Durchgang 16 zu
beobachten sind und im Anschluss dabei helfen sollen, eine validierbare Testumgebung zu schaffen,
lassen sich wie folgt zusammenfassen. Dabei sind diese Ergebnisse nur vorläufig zu interpretieren und
bedürfen noch weiteren ausführlichen Untersuchungen:

```
● Erhöhte 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾 , im Durchschnitt schlechtere Modell-Performance.
● Erhöhte 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛 , führt zu einer besseren Modell-Performance, außer bei einer
𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾 = 10.
● Erhöhte 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 , ergibt eine bessere Modell-Performance, außer bei einer
𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 5.
● Erhöhung 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠 bei 𝐾= 10 bessere Modell-Performance als bei einer
𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾 = 3 und 𝐾= 5.
● Random Auswahl Clients pro Runde. = 3 Clients bessere Ergebnisse als bei 𝐾= 10.
● Erhöhung der 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 bei 𝐾= 10 bessere Ergebnisse als bei einer
𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 5.
```
Dabei ist wichtig zu erwähnen, dass diese Erkenntnisse einzig und allein aus den Ergebnissen der
Testdurchführung unter den bereits beschriebenen Experiment-Bedingungen entstanden sind und
stark bei der Verwendung eines anderen Modells, Daten etc. abweichen können. Die hier
interpretierte Modell-Performance bezieht sich vorrangig auf die Werte 𝐺𝑀𝐴 und 𝐺𝑀𝑅, da die
𝐺𝐶𝐴 und der 𝐺𝐶𝑅 für die Klassen 1 und 9 in ihrer Gewichtung einen nicht allzu großen Beitrag für die
Stabilität des Modells liefern.

6.2.3.2 Durchschnitts-Performance des Basis Set-Up
Nachdem die Grundparameter für die anschließenden Testdurchläufe evaluiert wurden, sollten nun
die Durchschnittswerte der Performance-Metriken des zugrundeliegenden Modells und Daten erfasst
werden, da das Modell, durch die Verwendung von Non-IID Daten und einer Random-Auswahl an
Clients pro Runde sehr starken Schwankungen in Hinblick auf die Datenverteilung ausgesetzt ist und
jeder Testdurchlauf somit stark abweichende Ergebnisse erzielt. Um später jedoch zu prüfen, wie stark
die Auswirkung die Erhöhung der Poisoning Rate innerhalb des Systems auf die Modell-Performance
wirkt, sollten die Durchschnittswerte von fünf Durchgängen anhand von nicht vergifteten Clients
durchgeführt werden und diese mit fünf Durchgängen mit vergifteten Clients gegenübergestellt
werden, um so einigermaßen vergleichbare Werte zu erreichen.

_Testdurchlauf 6. Durchschnittsperformance Basis Set-Up_

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
1 0.8246 0.8229 0.9771 0.9705 0.9039 0.8176
2 0.8768 0.8766 0.9420 0.9911 0.9885 0.2220
3 0.7646 0.7729 1.0 0.9671 0.3057 0.6422
4 0.9090 0.9090 0.9962 0.8603 0.9436 0.8305
5 0.9440 0.9441 0.9866 0.9484 0.9797 0.8017
Durchschnitt 0.8638 0.8651 0.9803 0.9474 0.8242 0.6628
Tabelle 2.0


Wie aus der in Tabelle 2.0 dargestellten Auswertung ersichtlich ist, weist das Modell bei einer
fünffachen Wiederholung des Trainings mit dem Basis-Setup eine 𝐺𝑀𝐴 von 0,8638 auf, was einem
prozentualen Anteil von ca. 86,4 % entspricht. Dieses Ergebnis ist als gut und stabil zu bewerten,
insbesondere vor dem Hintergrund, dass die Datengrundlage Non-IID-Daten umfasst. Im Rahmen der
nachfolgenden Testreihe erfolgt eine Evaluierung der Auswirkungen einer potenziellen Vergiftung von
Clients auf ein FL-System unter Verwendung des zuvor beschriebenen Basis-Setups.

#### 6.2.4 Erhöhung der Poisoning-Rate, Auswirkung auf Modell-Performance...................................

Anhand der Erhebung soll getestet werden, inwiefern die Erhöhung der 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅 einen
Einfluss auf die Modell-Performance besitzt. Es wurde wiederum das Basis Set-Up verwendet.

_Testdurchlauf 7. Poisoning Rate 14,3% (Performance-Durchschnitt)_

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Poisoning
Rate (PR)
1 0.7542 0.7677 0.875 0.8055 0.0061 0.7145 14,3%
2 0.9097 0.9080 0.9233 0.9056 0.9867 0.8275 14,3%
3 0.6430 0.6399 0.4450 0.0 0.9497 0.0 14,3%
4 0.7692 0.7697 0.7357 0.2218 0.8317 0.0604 14,3%
5 0.7714 0.7708 0. 9793 0.9540 0.9612 0.1645 14,3%
Durchschnitt 0.7695 0.7712 0.7916 0.5773 0.7470 0.3533
Tabelle 3.0

In Tabelle 3.0 variieren die 𝐺𝑀𝐴 und der 𝐺𝑀𝑅 zwischen den einzelnen Durchgängen, wobei
Durchgang 2 die höchsten Werte (𝐺𝑀𝐴 = 0. 9097 ,𝐺𝑀𝑅 = 0. 9080 ) erreicht. Die Genauigkeiten der
Klasse 1 (𝐺𝐶 1 𝐴) und Klasse 9 (𝐺𝐶 9 𝐴) sind durch das Label Flipping stark beeinträchtigt, insbesondere
in Durchgang 3, in welcher der Wert 𝐺𝐶 9 𝐴 bei 0.0 liegt. Insgesamt zeigt die durchschnittliche 𝐺𝑀𝐴=
0. 7695 eine moderate Modellleistung. Der durchschnittliche Recall bei Klasse 1 ist mit 0.7470 relativ

```
Abbildung 15 : In der oberen Grafik wurden die einzelnen Performance-Metriken des Basis-Setups geplottet. Die
Darstellung auf der y-Achse erfolgt in Form einer prozentualen Angabe der einzelnen Performance-Ausprägungen,
während auf der x-Achse die jeweiligen Performance-Metriken abgebildet werden. Insgesamt sind die Resultate als
hoch zu bewerten, wobei jedoch ein geringer Global Class 9 Recall im Verhältnis zu den anderen Metriken zu
verzeichnen ist [Quelle: Eigene Darstellung].
```

hoch, während der für Klasse 9 mit 0.3533 deutlich niedriger ist, was auf eine größere Anfälligkeit der
Klasse 9 für den Angriff hinweist. Im Folgenden sind die einzelnen Werte als Plot dargestellt (siehe
Abb. 17).

_Testdurchlauf 8. Poisoning Rate 28,6% (Performance-Durchschnitt)_

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Poisoning
Rate (PR)
1 0.7417 0.5387 0.9908 0.6344 0.2854 0.4558 28,6%
2 0. 7121 0. 7189 0. 7186 0. 1691 0. 3488 0. 2438 28,6%
3 0. 7121 0. 7251 0.5 0.32 0. 0017 0. 0079 28,6%
4 0. 6564 0. 6595 0. 6548 0. 0069 0. 5383 0. 0029 28,6%
5 0. 8094 0. 8059 0. 7411 0. 8767 0. 9911 0. 6699 28,6%
Durchschnitt 0.7263 0.6896 0.7210 0.4014 0.4330 0.2760
Tabelle 3.1

Wiederum in Tabelle 3.1 sind die 𝐺𝑀𝐴 und der 𝐺𝑀𝑅 sind im Vergleich zur vorherigen Tabelle 3.0
weiter gesunken, wobei die 𝐺𝑀𝐴 im Durchschnitt auf 0.7263 und der 𝐺𝑀𝑅 auf 0.6896 fällt. Die
Genauigkeiten der Klasse 1 (GC1A) und Klasse 9 (GC9A) sind ebenfalls stark beeinträchtigt.

Im weiteren Vergleich zur vorherigen Tabelle 3.0, in der die 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 (𝑃𝑅) bei 14,3% lag,
zeigen die Ergebnisse eine Verschlechterung der Modellleistung bei erhöhter Poisoning Rate. Die
durchschnittliche 𝐺𝑀𝐴 ist von 0.7695 auf 0.7263 (Reduzierung von ca. 4,3%) gesunken und der
durchschnittliche 𝐺𝑀𝑅 von 0.7712 auf 0.6896 (Reduzierung von ca. 8,1%).

Die Klassen 1 und 9 sind noch ungleichmäßiger betroffen, was durch die niedrigen Durchschnittswerte
von 𝐺𝐶 1 𝐴 in Tabelle 3.1 von 0.7210 zu Tabelle 3.0 mit 0.7916 und 𝐺𝐶 9 𝐴 in Tabelle 3.1 0.4014 zum

```
Abbildung 16 : Vergleicht man die hier vorliegende Auswertung mit der Grafik in Abb. 16 ist es auffällig, dass die
Performance-Metriken das allgemeine Performance-Niveau des Basis Set-Up ohne vergiftete Clients in fast jeder
Metrik unterschreiten. Auf der Y-Achse sind wieder die einzelnen Performance-Ausprägungen in Prozent und auf der
X-Achse die jeweiligen Performance-Metriken dargestellt [Quelle: Eigene Darstellung].
```

𝐺𝐶 9 𝐴 in Tabelle 3.0 0.5773 verdeutlicht wird. Besonders auffällig ist der weiter fortschreitende
Rückgang des Recalls für Klasse 9 (𝐺𝐶 9 𝑅) auf durchschnittlich 0.2760, was die größere Anfälligkeit der
Klasse 9 gegenüber der Klasse 1 bei einer Label Flipping Attack bestätigt.

_Testdurchlauf 9. Poisoning Rate 42,9% (Performance-Durchschnitt)_

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Poisoning
Rate (PR)
1 0.5473 0.5428 0.5249 0.0666 0.8528 0.0009 42,9%
2 0.6747 0.6853 0.0 0.3193 0.0 0.4608 42,9%
3 0.6904 0.6908 0.4510 0.2083 0.8 0.0099 42,9%
4 0.6419 0.6444 0.9557 0.3726 0.5515 0.1377 42,9%
5 0.6539 0.6502 0.7379 0.1010 0.7665 0.0198 42,9%
Durchschnitt 0.6416 0.6427 0.5339 0.2135 0.5941 0.1258
Tabelle 3.2

Der Trend über die Verschlechterung der Metriken 𝐺𝑀𝐴 über 𝐺𝑀𝑅 bei steigender
𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅, zeigt sich auch in Tabelle 3.2, wobei die 𝐺𝑀𝐴 im Durchschnitt auf 0.6416 und
der 𝐺𝑀𝑅 auf 0.6427 im Vergleich zur vorherigen Tabelle fällt. Die Genauigkeiten der Klasse 1 mit
𝐺𝐶 1 𝐴 und Klasse 9 mit 𝐺𝐶 9 𝐴 sind weiter deutlich beeinträchtigt.

Im Vergleich zur vorherigen Tabelle mit einer 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅= 28 ,6% zeigen die Ergebnisse
eine zusätzliche Verschlechterung der Modellleistung. Die durchschnittliche 𝐺𝑀𝐴 ist von 0.7263 auf
0.6416 und der durchschnittliche 𝐺𝑀𝑅 von 0.6896 auf 0.6427 gesunken. Die spezifischen
Klassengenauigkeiten haben sich ebenfalls verschlechtert, wobei 𝐺𝐶 1 𝐴 im Durchschnitt auf 0.5339
und 𝐺𝐶 9 𝐴 auf 0.2135 gefallen ist.

```
Abbildung 17 : Eine Erhöhung der Poisoning Rate PR führt jedoch zu einer weiteren Abnahme der Modellleistung im
Vergleich zu den vorherigen Testdurchläufen. Die Y-Achse zeigt die einzelnen Performance-Ausprägungen in Prozent,
während auf der X-Achse die Performance-Metriken abgebildet sind [Quelle: Eigene Darstellung].
```

Es zeichnet sich ein Trend ab, dass bei Zunahme der 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅 parallel eine Abnahme der
allgemeinen Modell-Performance zu bemerken ist. Um dies vollständig zu validieren, wird die
𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅 im abschließenden Testdurchlauf stückweise bis auf 100% erhöht.

#### 6.2.5 Auswirkung der Modell-Performance bei Steigerung der Poisoning Rate

Eine Poisoning Rate 𝑃𝑅 > 42 ,9% ist für ein realistisches Szenario schwer denkbar, dennoch soll
anhand einer weiteren Erhöhung der Poisoning Rate überprüft werden, ob der Trend der Reduzierung
der allgemeine Modellleistung bei Zunahme der 𝑃𝑅 weiter anhält.

_Testdurchgang 10. Steigerung der Poisoning Rate PR_

Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Poisoning
Rate (PR)
1* 0.7695 0.7712 0.7916 0.5773 0.7470 0.3533 14,3%
2* 0.7263 0.6896 0.7210 0.4014 0.4330 0.2760 28,6%
3* 0.6416 0.6427 0.5339 0.2135 0.5941 0.1258 42,9%
4 0.6402 0.6482 0.9042 0.0209 0.1497 0.0118 57,1%
5 0.5849 0.5941 0.0 0.0062 0.0 0.0069 71,4%
6 0.6967 0.7085 0.0 0.0026 0.0 0.0029 85,7%
7 0.6202 0.6298 0.0011 0.0031 0.0008 0.0029 100%
Tabelle 3.3

```
Abbildung 18 : Eine Erhöhung der Poisoning Rate PR auf 42,9 % resultiert in einer weiteren, rapiden Abnahme der
Modellleistung, wie in der oberen Grafik dargestellt. [Quelle: Eigene Darstellung].
```

Die finale Interpretation der obigen Tabelle zeigt, dass eine steigende Poisoning Rate zu einer
signifikanten Verschlechterung der Modellleistung führt. Besonders betroffen sind die spezifischen
Klassen 1 und 9, deren Genauigkeiten und Recall-Werte drastisch sinken. Bei sehr hohen Poisoning
Rates 𝑃𝑅≥ 57 ,1% approximieren 𝐺𝐶 1 𝐴 und 𝐺𝐶 9 𝐴 den Wert 0.0, was die Fähigkeit des Modells,
diese Klassen korrekt zu klassifizieren, vollständig beeinträchtigen würde.

```
Abbildung 19 : Diese und die folgenden Abbildungen (Abb. 21, 22 und 23) beziehen sich auf die Tabelle 3.3.
Dabei wird dargestellt, inwiefern die Modelleistung abnimmt, sobald die Poisoning Rate PR zunimmt. Auf
der X-Achse ist die jeweilige Poisoning Rate PR als Prozentwert dargestellt, während auf der X-Achse der
erreichte Global Model Accuracy Wert aufgeführt wurde Die rote Linie (auch in Abb. 21, 22 und 23) ist die
Regression der einzelnen GMA-Werte als Trendverlauf [Quelle: Eigene Darstellung].
```
```
Abbildung 20 : Äquivalent zur Abb.20 ist auf der Y-Achse der Global Class Recall Wert bzw. Global Model Recall Wert
dargestellt und auf der Y-Achse die einzelnen Poisoning Rates. Auch hier kann anhand der Trendlinie beobachtet
werden, dass bei einer Zunahme der Poisoning Rate PR, die GMR abnimmt [Quelle: Eigene Darstellung].
```

##### 37

```
A b b i l d u n g 2 3 : W
```
_Abbildung 21 : Die nachfolgende Grafik zeigt eine kombinierte Darstellung der Werte GC1A und GC1R. Die Werte GC1A und GC1R sind
in unterschiedlichen Farben dargestellt, wobei der Wert GC1A in Blau und der Wert GC1R in rötlicher Farbe abgebildet ist. Die Y-Achse
zeigt jeweils den erreichten Performance-Wert, während die X-Achse die Poisoning Rate PR darstellt. Auch in dieser Darstellung zeigt
sich ein konsistenter Abwärtstrend bei beiden Werten, parallel zur Zunahme der Poisoning Rate. Diesbezüglich ist festzuhalten, dass
der Recall-Wert im Durchschnitt geringer ist als der Accuracy-Wert der Klasse 1 [Quelle: Eigene Darstellung]._

```
Abbildung 22 : Analog zu Abbildung 22 erfolgte die Darstellung der einzelnen Ergebniswerte auch für die Klasse 9 nach
demselben Prinzip. Es fällt auf, dass die Werte der Klasse 9 im Allgemeinen deutlich geringer sind als die Werte der
Klasse 1. Eine Reduzierung der Performance des Modells ist jedoch – wie in den Abbildungen 20, 21 und 22 dargestellt
```
_- bei ansteigender Poisoning-Rate PR zu verzeichnen [Quelle: Eigene Darstellung]._


Die Beobachtung der rasanten Abnahme der Werte der 𝐺𝐶𝐴 und 𝐺𝐶𝑅, der Klasse 1 und Klasse 9 bei
bereits einem vergifteten Client (siehe im Vergleich Basis Set-Up Performance Tabelle 2.0) zeigt,
welchen starken Einfluss die vergifteten Clients auf die allgemeine Modell-Performance nehmen.

Es ist daher wichtig einerseits ein möglichst robustes FL-System zu konstruieren, welches anhand
seiner Parameter (Clientanzahl, Batch Size usw.) derart eingestellt wurde, dass es trotz einer
Vergiftung zu einem geringen Abfall der Modellleistung führt, sowie vergiftete Clients insofern es
möglich ist, präventiv vor der Teilnahme an dem System ausgeschlossen werden (vgl. Defensive
Maßnahmen gegen eine Label Flipping Attack).

Da bereits eine Poisoning Rate 𝑃𝑅= 14 ,9% (1 Client von 7 Clients) einen bemerkbaren Einfluss auf
das zu testende FL-System ausgeübt hat, wird in der Folge weiter mit dieser spezifischen Poisoning
Rate gearbeitet, da auch, wie bereits erwähnt, eine geringere Poisoning Rate, ein wesentlich
realistisches Szenario für spätere Einsatzmöglichkeiten aufweist.

_Gewichteter Endwert*_

Anhand des Basis Set-Up werden die folgenden Parameter (vgl. Testparameter unten) aktualisiert und
getestet und jeweils der Durchgang mit der höchsten Modell-Performance grün markiert. Die
allgemeine Modell-Performance wird mit einem sog. Gewichteten Endwert zusammenaddiert, um
eine numerische Vergleichbarkeit zwischen den einzelnen Testdurchläufen zu erreichen. Der
Gewichtete Endwert berechnet sich nach der Formel:

```
𝐺𝑒𝑤𝑖𝑐ℎ𝑡𝑒𝑡𝑒𝑟 𝐸𝑛𝑑𝑤𝑒𝑟𝑡=(𝐺𝑀𝐴+𝐺𝑀𝑅) 𝑥 1. 0 +(𝐺𝐶 1 𝐴+𝐺𝐶 9 𝐴+𝐺𝐶 1 𝑅+𝐺𝐶 9 𝑅) 𝑥 0. 1
```
Wobei 𝐺𝐶 1 𝐴 und 𝐺𝐶 9 𝐴 für Global Class Accuracy von Klasse 1 und 9 steht, sowie 𝐺𝐶 1 𝑅 und 𝐺𝐶 9 𝑅 für
Global Class Recall der Klasse 1 und 9.

_Testparameter_

_1. Erhöhung_ 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟
_2. Erhöhung_ 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛
_3. Erhöhung_ 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠
_4. Erhöhung_ 𝐶𝑙𝑖𝑒𝑛𝑡𝑠 𝑝𝑟𝑜 𝑅𝑢𝑛𝑑𝑒 𝑐𝑝𝑟

_Testdurchgang 11. Auswirkung Erhöhung Rundenanzahl (r) mit Basis Set-Up_

```
Durchgang Rundenanzahl 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert*
1 1 0.6592 0.6540 0.7535 0.6883 0.9726 0.2101 1.3237
2 3 0.8183 0.8158 0.7918 0.8194 0.9788 0.8097 1.9774
3 5 0. 8773 0.8769 0. 9950 0. 9419 0.8845 0.9494 1.9126
4 10 0.7721 0.7658 0.9750 0.6689 0.9647 0.7670 1.8754
5 20 0.7872 0.7838 0.5450 0.8044 0.9964 0.9048 1.8960
6 50 0.6460 0.6435 0.7001 0.1207 0.8907 0.0525 1.4659
```
Tabelle 4.0

Es zeigt sich anhand von Tabelle 4.0, dass mit zunehmender 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 die 𝐺𝑀𝐴 und 𝐺𝑀𝑅
zunächst ansteigen und dann wieder abfallen. Insbesondere bei 𝑟= 5 wird die höchste 𝐺𝑀𝐴 (0.8773)
und 𝐺𝑀𝑅 (0.8769) erreicht, was auf eine gute Modellleistung hinweist.


Die Genauigkeit der Klassen 1 und 9 (𝐺𝐶 1 𝐴 und 𝐺𝐶 9 𝐴) sowie deren Recall (𝐺𝐶 1 𝑅 und 𝐺𝐶 9 𝑅) sind bei
dieser Rundenanzahl ebenfalls hoch, was eine ausgewogene und robuste Performance gegenüber
dem Label Flipping dieser Klassen zeigt. Ein Gewichteter Endwert von 1.9126 bei 5 Runden bestätigt
diese Beobachtung. Bei einer weiteren Erhöhung der 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 auf 10, 20 und 50 Runden
sinken die Werte für 𝐺𝑀𝐴 und 𝐺𝑀𝑅, sowie die Genauigkeiten der Klasse 1 und Klasse 9 wieder, was
auf eine Verschlechterung der Modellleistung und eine geringere Robustheit hinweist. Es wird auf
Grundlage der Testergebnisse eine 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟= 5 gewählt werden, um so eine optimale
Balance zwischen Robustheit und Modellleistung zu erreichen.

_Testdurchgang 12. Auswirkung Erhöhung Epochenanzahl (en) mit Basis Set-Up_

Durchgang Epochenanzahl 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert*
1 1 0. 6349 0. 6302 0. 9805 0. 8728 0. 9797 0. 3062 1.5790
2 3 0. 3375 0. 3267 0. 1591 0.0 1.0 0.0 0.7801
3 5 0.9103 0.9098 0.9645 0.7693 0.9823 0.9554 2.1872
4 10 0.8470 0.8474 0.9894 0.9517 0.8264 0.7423 2.0453
5 20 0.7235 0.7220 0.7593 0.0 0.9841 0.0 1.6198
6 50 0. 6938 0. 6977 0. 9953 0.5 0. 5603 0. 0019 1.5972
Tabelle 4.1

Interpretiert man Tabelle 4.1, erreicht die 𝐺𝑀𝐴 (0.6349) und der 𝐺𝑀𝑅 (0.6302) bei einer
𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛= 1 vergleichbare niedrige Werte, während die Metriken 𝐺𝐶 1 𝐴 und 𝐺𝐶 9 𝐴 recht
hoch sind. Bei einer 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛= 3 sinken die Werte für 𝐺𝑀𝐴 und 𝐺𝑀𝑅 jedoch drastisch,
was auf eine schlechte Modellleistung und Robustheit hinweist. Bei 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛= 5
erreichen die 𝐺𝑀𝐴 (0.9103) und der 𝐺𝑀𝑅 (0.9098) ihren vorläufigen höchsten Wert, ebenso wie die
Klassengenauigkeiten für 𝐺𝐶 1 𝐴 und 𝐺𝐶 9 𝐴. Der Gewichtete Endwert von 2.1872 ist ebenfalls der
höchste innerhalb der Tabelle 4.1. Bei einer weiteren Erhöhung der 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛 auf 10, 20
und 50 Epochen sinken die Werte wieder, obwohl 𝐺𝑀𝐴 und 𝐺𝑀𝑅 bei 10 Epochen noch relativ hoch
bleiben. Die Ergebnisse zeigen, dass die optimale Epochenanzahl bei 𝑒𝑛= 5 im Verhältnis zu den
anderen Ergebnissen liegt.

_Testdurchgang 13. Auswirkung Erhöhung Batch Size (bs) mit Basis Set-Up_

```
Durchgang Batch
Size
```
𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert*
1 4 0. 7473 0. 7477 0. 7739 0. 2373 0. 8176 0. 0931 1.6871
2 8 0.7620 0.7587 0.7119 0.5733 0.9973 0.7670 1.5207
3 16 0.8626 0.8607 0.9104 0.9561 0.9859 0.4103 2.0495
4 32 0.7408 0.7415 0.9861 0.3517 0.7550 0.1575 1.7073
5 64 0.6833 0.6813 0.6935 1.0 0.9929 0.0079 1.6340
6 128 0.6701 0.6650 0.7300 0.4661 0.9938 0.9018 1.6442
Tabelle 4.2

Mit einer 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠= 4 erreicht die 𝐺𝑀𝐴 (0.7473) und der 𝐺𝑀𝑅 (0.7477) in Tabelle 4.2, wobei
die Genauigkeiten für 𝐺𝐶 1 𝐴 und 𝐺𝐶 9 𝐴 mittlere Werte zeigen. Bei einer 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠= 8 steigen
die Werte 𝐺𝑀𝐴 und 𝐺𝑀𝑅 leicht an, die Performance bleibt insgesamt stabil. Mit einer 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒
𝑏𝑠= 16 erreichen die 𝐺𝑀𝐴 (0.8626) und der 𝐺𝑀𝑅 (0.8607) ihre höchsten Werte, ebenso wie die
Klassengenauigkeiten für 𝐺𝐶 1 𝐴 (0.9104) und 𝐺𝐶 9 𝐴 (0.9561) und weist auf eine gute Anpassung und
Robustheit hin, da auch der allgemeine Gewichtete Endwert mit 2.0495 in Relation zu den anderen
Werten hoch ist.


Bei weiterer Erhöhung der 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠= 32 sinken die allgemeinen Werte wieder leicht, wobei die
𝐺𝑀𝐴 auf 0.7408 und der 𝐺𝑀𝑅 auf 0.7415 fällt. Bei den B𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒𝑠 𝑏𝑠= 64 und 𝑏𝑠= 128 bleiben
die Werte weiterhin relativ niedrig, wobei insbesondere bei 𝑏𝑠= 64 die 𝐺𝐶 9 𝐴 den höchsten Wert
von 1.0 erreicht, aber der 𝐺𝐶 9 𝑅 sehr niedrig bleibt (0.0079), was auf eine unausgewogene Leistung
bzw. sogar auf ein Overfitting hinweisen könnte. Die 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠= 16 zeigt von allen Durchgängen
somit das beste Ergebnis.

_Testdurchgang 14. Auswirkung Clients pro Runde (cpr) mit Basis Set-Up_

```
Durchgang Clients
pro
Runde
```
```
𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert*
```
1 1 0. 9648 0. 9648 0. 9868 0. 9868 0. 9519 0. 9894 2.3210
2 2 0.7835 0.7798 0.9193 0.9661 0.9947 0.3111 1.8824
3 3 0.7860 0.7841 0.9777 0.6530 0.9303 0.8374 1.9099
4 4 0.8874 0.8846 0.9797 0.9158 0.9823 0.8731 2.1470
5 5 0.8568 0.8535 0.9130 0.7230 0.9903 0.9702 2.0699
6 6 0. 3819 0. 3771 0. 7869 0.0 0. 6378 0.0 0.9014
7 7 0.2691 0.2565 0.1594 0.7134 1.0 0.1159 0.7244
Tabelle 4.3

Mit nur einem Client pro Runde (𝑐𝑝𝑟= 1 ) erreicht, wie in Tabelle 4.3 zusehen, die 𝐺𝑀𝐴 0.9648 und
der 𝐺𝑀𝑅 ebenfalls 0.9648, was auf eine sehr hohe Modellleistung und Robustheit hinweist. Diese
Einstellung führt zum höchsten gewichteten Endwert von 2.3210. Bei zwei Clients pro Runde sinken
die Werte für 𝐺𝑀𝐴 und 𝐺𝑀𝑅 merklich auf 0.7835 und 0.7798, wobei die Genauigkeit der Klasse 9
(𝐺𝐶 9 𝐴) auf 0.9661 hoch bleibt.

Mit 𝑐𝑝𝑟= 3 stabilisieren sich die Werte leicht, wobei die 𝐺𝑀𝐴 und der G𝑀𝑅 auf 0.7860 bzw. 0.7841
bleiben und insgesamt der gewichtete Endwert 1.9099 erreicht. Bei 𝑐𝑝𝑟= 4 verbessern sich die
Werte wieder signifikant, wobei die 𝐺𝑀𝐴 auf 0.8874 und der 𝐺𝑀𝑅 auf 0.8846 steigt, mit dem
höchsten gewichteten Endwert von 2.1470.

Ab 𝑐𝑝𝑟= 5 beginnen die Werte wieder zu sinken, obwohl sie in ihrem Niveau allgemein hoch bleiben,
wobei die 𝐺𝑀𝐴 bei 0.8568 und der 𝐺𝑀𝑅 bei 0.8535 liegen. Ab 𝑐𝑝𝑟≥ 6 verschlechtern sich die Werte
drastisch, insbesondere die GMA und der GMR, was auf eine deutlich reduzierte Robustheit hinweist.
Die Ergebnisse zeigen, dass eine optimale Anzahl von vier Clients pro Runde bzw. 𝑐𝑝𝑟= 4 gewählt
werden sollte.

_Allgemeines Ergebnis Basis Set-Up_

Die Analyse der vier Tabellen (4.0, 4.1, 4.2 und 4.3) zeigt, wie unterschiedliche Parameter-
Einstellungen die Robustheit eines FL-Systems gegenüber Label Flipping Attacken beeinflussen. Durch
die Erhöhung der 𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟 wurde festgestellt, dass eine Einstellung von 𝑟= 5 die beste
Leistung und Robustheit, mit einer 𝐺𝑀𝐴 von 0.8773 bietet.

Bei der Anpassung der 𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛 zeigte sich, dass 𝑒𝑛= 5 optimal sind, was durch die
höchste 𝐺𝑀𝐴 von 0.9103 und einem gewichteten Endwert von 2.1872 bestätigt wird.

Bei der Untersuchung der 𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠 führte eine Einstellung von 𝑏𝑠= 16 zur besten Performance
mit einer 𝐺𝑀𝐴 von 0.8626 und einem gewichteten Endwert von 2.0495.

Schließlich wurde festgestellt, dass vier Clients pro Runde bzw. 𝑐𝑝𝑟= 4 die optimale Anzahl ist, da
diese Einstellung eine 𝐺𝑀𝐴 von 0.8874 und einen gewichteten Endwert von 2.1470 erreicht hatte.


Zusammengefasst ergibt sich die beste Parametereinstellung aus 5 Runden, 5 Epochen, einer Batch
Size von 16 und vier Clients pro Runde, um eine gewisse Robustheit gegenüber einer Label Flipping
Attack zu erreichen.

_Testdurchgang 15. Durchschnittsperformance des Basis Set-Up bei Poisoning Rate 14,9%_

Tabelle 5.0

Trotz einer 𝑃𝑅 = 14 ,9% bzw. einem vergifteten Client bei einer 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 7 in Tabelle 5.0
ist die Performance des Basis Set-Up noch einigermaßen stabil. Es zeigt jedoch noch einmal, welchen
starken Einfluss schon ein einziger vergifteter Client auf ein globales Modell ausüben kann und
verdeutlicht, dass das präventive Aussortieren vergifteter Clients womöglich die beste Art der
Verteidigung darstellen könnte

6.2. 5 .1 Non-IID vs. IID-Daten
Eine nähere Beschreibung der Thematik Non-IID Daten findet sich in Abschnitt Daten, Preprocessing
und Non-IID. Diese Testdurchführung hat es zur Aufgabe, aufgrund der Versuchsfragen den
Unterschied von Non-IID Daten zum normalen (IID) MNIST-Datensatz zu untersuchen und ob es zu
signifikanten Unterschieden bei der Trainings-Teilnahme eines vergifteten Clients gibt. Es wurde
wiederum das Basis Set-Up verwendet. Die ersten vier Testdurchläufe wurden ohne vergiftete Clients,
die weiteren vier Testdurchläufe mit vergifteten Clients bzw. einer 𝑃𝑅=50% durchgeführt.

_Testdurchgang 16. Non-IID vs. Normale Daten (nicht vergiftet)_

```
Durchgang Non-
IID
```
𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert*
1 Ja 0.8245 0.8228 0.9567 0.8434 0.8969 0.8810 2.0051
2 Ja 0.8891 0.8871 0.8983 0.9401 0.9964 0.7789 2.1375
3 Nein 0.8647 0.8634 0.9351 0.6634 0.9268 0.8870 2.0693
4 Nein 0.8302 0.8294 0.9306 0.8680 0.9462 0.5996 1.9940
Tabelle 6.0

_Testdurchgang 17. Non-IID vs. Normale Daten (Poisoning Rate PR=50%)_

```
Durchgang Non-
IID
```
𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert*
1 Ja 0.7221 0.7220 0.7366 0.024 0.6951 0.0029 1.5899
2 Ja 0.7634 0.7595 0.4672 0.1923 0.9867 0.0049 1.6880
3 Nein 0.7360 0.7432 0.9966 0.3701 0.2643 0.9762 1.7399
4 Nein 0.7204 0.7140 0.8397 0.6723 0.9744 0.3151 1.7145
Tabelle 6.1

```
Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
```
##### 1 0.9265 0.9266 0.9723 0.9488 0.9303 0.9008

##### 2 0.7709 0.7662 0.8435 0.8546 0.9973 0.5827

##### 3 0.8806 0.8781 0.9936 0.9819 0.9665 0.8107

##### 4 0.8888 0.8888 0.8953 0.7815 0.9726 0.9217

##### 5 0.8873 0.8892 0.9928 0.9441 0.7392 0.8037

```
Durchschnitt 0.8708 0.8697 0.9395 0.9021 0.9211 0.8039
```

_Vergleich Non-IID Daten und IID-Daten_

Anhand der oben dargestellten Testdurchläufe in Tabelle 6.0 und 6.1, anhand von Non-IID Daten und
wiederum einem normalen Datensatz, sind vorerst keine allzu großen und auffälligen Abweichungen
zwischen beiden Datenausprägungen zu identifizieren. Es sollten hierfür in Zukunft noch wesentlich
ausführlichere Testdurchläufe absolviert werden, um konkrete Werte und Ergebnisse klassifizieren zu
können.

6.2. 5 .2 Label Flipping Attack bei Klasse 1 und 9 und 3 und 8

In einer der letzten Testdurchführung wird die Versuchsfrage 5 (vgl. Versuchsfragen) erörtert, ob es
einen Unterschied in der Modell-Performance gibt, wenn eine Label Flipping Attack anhand der Labels
1 und 9, sowie äquivalent die Labels 3 und 8 durchgeführt wird.

_Testdurchgang 18. Label Flipping Attack bei Klasse (1 und 9) und (3 und 8)_

Durchgang Klasse 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R Gewichteter
Endwert
1 1 und 9 0.7505^ 0.7586^ 0.3349^ 0.0043^ 0.3744^ 0.0019^ 1.5806
2 3 und 8 0.9077^ 0.9065^ 0.9717^ 0.8724^ 0.9682^ 0.9762^ 2.1930
3 1 und 9 0.8162^ 0.8218^ 0.96^ 0.1384^ 0.6132^ 0.0089^ 1.8100
4 3 und 8 0.8367^ 0.8364^ 0.7381^ 0.9109^ 0.9982^ 0.6897^ 2.0067
5 1 und 9 0.7890^ 0.7980^ 0.6960^ 0.0067^ 0.3753^ 0.0009^ 1.6948
6 3 und 8 0.7014^ 0.6996^ 0.8648^ 0.9723^ 0.9638^ 0.5569^ 1.7367
Tabelle 7.0

Ergebnis Testdurchgang 18

Es gibt signifikante Unterschiede in Tabelle 7.0 in den Ergebnissen zwischen den beiden Gruppen bzw.
Klassen 1 und 9 und Klassen 3 und 8.

Beim Label Flipping der Klassen 1 und 9 ist 𝐺𝑀𝐴 und 𝐺𝑀𝑅 durchweg niedriger als bei Klasse 3 und 8.
Beispielsweise liegt die 𝐺𝑀𝐴 in Durchgang 1 bei 0.7505 und die 𝐺𝑀𝑅 bei 0.7586, mit besonders
niedrigen Werten für 𝐺𝐶 1 𝐴 (0.3349) und 𝐺𝐶 9 𝐴 (0.0043). Ähnlich niedrige Werte sind auch in den
Durchgängen 3 und 5 zu beobachten (ebenfalls ist hier die Klasse 1 und 9 getestet worden). Auch der
Recall für Klasse 9 (𝐺𝐶 9 𝑅) ist niedrig, was darauf hinweist, dass das Modell stark beeinträchtigt ist,
wenn diese Klassen geflippt werden.

Bei Angriffen auf die Klassen 3 und 8 zeigen die Ergebnisse insgesamt höhere Werte in 𝐺𝑀𝐴 und 𝐺𝐶𝐴.
Beispielsweise liegt die 𝐺𝑀𝐴 in Durchgang 2 bei 0.9077 und die 𝐺𝐶𝐴 bei 0.9065, mit wiederum hohen
Werten für die Metriken 𝐺𝐶 1 𝐴 (0.9717) und 𝐺𝐶 9 𝐴 (0.8724). Ähnliche Tendenzen sind in den
Durchgängen 4 und 6 zu sehen. Der Recall bzw. 𝐺𝐶𝑅 für beide Klassen 3 und 8 bleibt in Relation zu
Klasse 1 und 9 hoch, was darauf hinweist, dass das Modell weniger anfällig für Angriffe auf diese
Klassen ist. Es wird daher die Vermutung aufgestellt, dass manche Klassen gegenüber einer Label
Flipping Attack scheinbar anfälliger sind als andere Klassen.


_Testdurchgang 19. Steigerung der Poisoning Rate_

```
Durchgang Poisoning
Rate
```
```
𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
```
##### 1 25% (1) 0.7448 0.7425 0.9941 0.8348 0.8986 0.8116

##### 2 50% (4) 0.7578^ 0.7554^ 0.9497^ 0.8372^ 0.9823^ 0.3924^

##### 3 66% (8) 0.6935^ 0.6881^ 0.8911^ 0.6125^ 0.9885^ 0.8632^

##### 4 75% (12) 0.5708 0.5648 0.7330 0.8863 0.9603 0.3478

##### 5 80% (16) 0.5037 0.4957 0.3058 0.9166 0.9982 0.0327

Tabelle 8.0

Bei einer 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾= 20 wurde sukzessive die 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅 pro Durchgang erhöht.

Anhand der Werte innerhalb der Tabelle 8.0 lässt sich die Vermutung aufstellen, dass eine Steigerung

#### der 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅 zu einer parallelen Reduzierung der Modellleistung führen kann.

#### 6.2.6 Validierung und Interpretation eigene Testdurchführung

Die Experimente und die aus den Tabellen gewonnenen Erkenntnisse liefern umfassende Antworten
auf die Versuchsfragen und zeigen teils klare Muster und Trends auf.

_1. Wie viele vergiftete Clients innerhalb eines FL-Systems müssen in Relation zu nicht vergifteten Clients
auftreten, dass diese eine messbare Auswirkung auf das Endresultat haben?_

Bereits bei einem niedrigen Prozentsatz an vergifteten Clients (z. B. 14,3% in Tabelle 3.0) ist eine
signifikante Auswirkung auf die Global Model Accuracy (𝐺𝑀𝐴) und den Global Model Recall (𝐺𝑀𝑅) zu
beobachten. Steigt die 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒 𝑃𝑅 weiter (z. B. auf 28,6% oder 42,9%), verschlechtern sich
die 𝐺𝑀𝐴 und 𝐺𝑀𝑅 deutlich, was zeigt, dass selbst wenige vergiftete Clients eine messbare und
signifikante Auswirkung haben können und diese Auswirkung scheinbar durch die Erhöhung der
vergifteten Clients verstärkt wird.

```
Abbildung 23 : Anhand der Abbildung
ist zu sehen, dass innerhalb der
einzelnen Messergebnisse des
Testdurchlaufs die GMA (siehe Y-
Achse) bei Steigerung der PR (siehe Y-
Achse) über die einzelnen
Testdurchgänge (siehe X-Achse)
abnimmt [Quelle: Eigene Darstellung].
```

_2. Welche Auswirkungen hat die Steigerung der Poisoning Rate auf das FL-System?_

Wie in Tabelle 8.0 zu sehen ist, ist bei einer Steigerung der Poisoning Rate 𝑃𝑅 eine konstante
Abnahme der Modelleistung zu verzeichnen. Dementsprechend kann die Vermutung aufgestellt
werden, dass eine Steigerung der Poisoning Rate in einem FL-System zu einer Reduzierung der Modell-
Performance beiträgt

_3. Wie anfällig ist der MNIST-Datensatz gegenüber einer Label Flipping Attack?_

Der MNIST-Datensatz ist relativ anfällig gegenüber Label Flipping Attacken, besonders bei den Klassen
1 und 9, wie aus den deutlich gesunkenen 𝐺𝑀𝐴- und 𝐺𝑀𝑅-Werten bei Angriffen auf diese Klassen
hervorgeht. Das Modell zeigt eine schlechtere Performance, wenn die Klassen 1 und 9 angegriffen
werden, im Vergleich zu Angriffen auf die Klassen 3 und 8.

_4. Wie verhält sich das verwendete DL-Modell bei einer Label Flipping Attack?_

Das verwendete DL-Modell zeigt eine deutliche Verschlechterung der Performance (sowohl 𝐺𝑀𝐴 als
auch 𝐺𝑀𝑅) bei Label Flipping Attacken, insbesondere bei höheren 𝑃𝑜𝑖𝑠𝑜𝑛𝑖𝑛𝑔 𝑅𝑎𝑡𝑒𝑠 𝑃𝑅 und bei
Angriffen auf bestimmte Klassen (1 und 9). Das Modell ist weniger robust gegenüber Angriffen auf
diese Klassen, was auf eine spezifische Anfälligkeit hinweist.

_5. Gibt es Differenzen in der Performance zwischen einer Label Flipping Attack, welche Klasse 1 und 9
oder 3 und 8 vertauscht?_

Angriffe auf die Klassen 1 und 9 führen zu einer erheblich stärkeren Verschlechterung der
Modellleistung als im Vergleich zu Angriffen auf die Klassen 3 und 8. Dies zeigt sich anhand deutlich
niedrigerer Werte für 𝐺𝑀𝐴 und 𝐺𝑀𝑅 sowie spezifischen Klassengenauigkeiten und -recalls (𝐺𝐶 1 𝐴,
𝐺𝐶 9 𝐴, 𝐺𝐶 1 𝑅 und 𝐺𝐶 9 𝑅) bei Angriffen auf die Klassen 1 und 9.

_6. Welche Kombination der Parameter (Clientanzahl, Epochenanzahl, Clients pro Runde, Batch Size)
führt zur höchsten Stabilität gegenüber einer Labelflipping-Attack. Bzw. welcher spezifische Parameter
hat auf die Stabilität den größten Einfluss?_

Die Parameter-Kombination aus 5 Runden, 5 Epochen, einer Batch Size von 16 und vier Clients pro
Runde, hat anhand der Testdurchläufe die jeweils größte Robustheit gegenüber einer Labe Flipping
Attack der Klasse 1 und 9 aufgezeigt (vgl. Durchschnitts-Performance des Basis Set-Up). Dabei scheint
es, dass eher die Kombination dieser Parameter zu einer Stabilität des Systems beiträgt als ein einziger
spezifischer Parameter.

_7. Sind Non-IID Daten im Vergleich zu normalen (nicht Non-IID) Daten anfälliger für eine Label Flipping
Attack?_

Die Experimente zeigen, dass Non-IID Daten besonders anfällig für Label Flipping Attacken sind. Dies
manifestiert sich in signifikanten Einbrüchen der Modellleistung (siehe Tabelle 6.1), was darauf
hindeutet, dass die Verteilung der Daten eine kritische Rolle in der Robustheit des Modells spielt.


#### 6.2.7 Optimale Parameter-Einstellungen für das Basis Set-Up

Aus den durchgeführten Experimenten ergeben sich die folgenden optimalen Parameter-
Einstellungen, um die Robustheit des Modells gegenüber Label Flipping Attacken zu maximieren und
später für den PoC anzuwenden:

𝑅𝑢𝑛𝑑𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑟: 5 Runden, da sie eine gute Balance zwischen Trainingszeit und Modellleistung
bieten.

𝐸𝑝𝑜𝑐ℎ𝑒𝑛𝑎𝑛𝑧𝑎ℎ𝑙 𝑒𝑛: 5 Epochen, was zur besten Modellleistung führt.

𝐵𝑎𝑡𝑐ℎ 𝑆𝑖𝑧𝑒 𝑏𝑠: 16, da diese Einstellung die beste Performance zeigt.

𝐶𝑙𝑖𝑒𝑛𝑡𝑠 𝑝𝑟𝑜 𝑅𝑢𝑛𝑑𝑒 𝑐𝑝𝑟: 4 Clients pro Runde, was zu einer optimalen Balance zwischen Stabilität und
Leistung des Modells führt.

𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾: 7 Clients pro FL-System stellen einen guten Kompromiss dar. Zudem führt eine zu
hohe Clientanzahl zu Leistungsproblemen bei der Ausführung des PoC.

## 7 Einführung Blockchain

Die Blockchain besteht, wie die Bezeichnung bereits vermuten lässt, aus einer Kette von Blöcken,
welche Informationen bzw. Daten enthalten [46].Letztendlich basiert diese Technologie schon auf
Arbeiten aus dem Jahr 1991, bei denen versucht wurde, digitale Dokumente mittels eines
Zeitstempels zu versehen, um so nachträgliche Manipulationen dieser Dokumente zu verhindern.
Jedoch erregte die Technologie bis zur Einführung 2009 und der Einführung von Bitcoin durch Satoshi
Nakamoto nur geringe Aufmerksamkeit.

In einer Blockchain hat jeder Teilnehmer Einsicht auf die beschriebenen Blöcke und dessen
Informationen. Eine der wichtigsten Eigenschaften hierbei ist jedoch, dass Informationen, welche als
Block in der Kette angelegt wurden, rückwirkend von keinem Teilnehmer verändert oder anderweitig
manipuliert werden können.

Jeder Block besteht aus den Daten bzw. aus dem Hash des vorherigen Datenblocks, wobei hierdurch
auch eindeutig eine Reihenfolge in der Kette aufgezeigt wird. Dabei besitzt auch jeder Block wiederum
einen eindeutigen Hash, welcher den Block dementsprechend eindeutig identifiziert. Das bedeutet,
dass beim Kreieren eines neuen Blocks dessen Hash ebenfalls neu kreiert wird. Sobald ein Block bzw.
dessen Informationen geändert werden, wird auch der Hash geändert (vgl. Hashing-Algorithmus).
Sobald Informationen eines Blocks geändert werden, somit also auch dessen Hashwert, so ist dieser
Hashwert nicht mehr konsistent mit den Hashwerten der darauffolgenden Blöcke bzw. des Hashwerts,
der dort gespeichert wurde. Hierdurch können andere Teilnehmer der Blockchain eindeutig
identifizieren, ob die Blockchain manipuliert wurde.

```
Abbildung 24 : Hier dargestellt eine Blockchain, welche mit dem Genesis-Block
initiiert wird, an welchen die einzelnen Blöcke sich anschließen [46].
```

Wie in der Abbildung 25 zu sehen, gibt es beispielhaft drei Blöcke innerhalb der Blockchain (in der
Regel sind es innerhalb einer Blockchain deutlich mehr Blöcke). Der erste Block, welcher auf keinen
spezifischen Block in der Kette verweist, wird Genesis Block genannt. Nachdem der Genesis Block mit
seinen Informationen und seinem Hash erstellt wurde, kann der folgende zweite Hash sich mit diesem
verknüpfen. Auch dieser zweite Block erstellt einen Hash, wobei dies immer so weiter in der Kette
geht. Angenommen, ein Angreifer möchte nun den ersten Block bzw. dessen Informationen
manipulieren, so ändert sich der Hash des ersten Blocks und die Verknüpfung mit allen weiteren
Blöcken in der Kette ist nicht mehr valide. Da ein Angreifer jedoch einfach die folgenden Blöcke und
deren Hashes neu berechnen könnte, um dessen Werte anzupassen und die Blockchain wieder zu
validieren, gibt es mehrere Konzepte das Erstellen neuer Blöcke in seiner Geschwindigkeit (z. B. durch
Proof of Work) zu begrenzen.

Proof of Work (PoW) ist ein Konsensmechanismus in verteilten Systemen, u.a. verwendet von Bitcoin,
der darauf abzielt, die Sicherheit und Integrität eines Netzwerks zu gewährleisten, indem Teilnehmer
gezwungen werden, einen bestimmten Arbeitsaufwand zu leisten, bevor sie neue Daten hinzufügen
dürfen. Wissenschaftlich betrachtet, basiert PoW auf der Idee, dass eine schwierige, aber
überprüfbare Rechenaufgabe gelöst werden muss, um einen Block in einer Blockchain zu validieren.
Diese Aufgabe erfordert erheblichen Rechenaufwand und Energie, was Manipulationen und Sybil-
Angriffe verhindert, da ein Angreifer mehr als die Hälfte der gesamten Rechenleistung des Netzwerks
kontrollieren müsste, um die Blockchain zu kompromittieren bzw. Blöcke zu verändern.
Dieser Arbeitsaufwand stellt sicher, dass der Prozess des Hinzufügens von Blöcken dezentralisiert
bleibt und keine einzelne Entität die Kontrolle übernehmen kann. Das alles trägt zur Sicherheit und
Dezentralisierung bei, da die Wahrscheinlichkeit eines erfolgreichen Angriffs proportional zur
aufgewendeten Rechenleistung und den damit verbundenen Kosten ist. PoW stellt somit sicher, dass
alle Teilnehmer einen wirtschaftlichen Anreiz haben, sich an die Regeln des Netzwerks zu halten und
ermöglicht gleichzeitig eine vertrauenswürdige und fälschungssichere Aufzeichnung von
Transaktionen [46].

Ethereum (vgl. Ethereum) verwendet eine andere Technologie als PoW, nämlich Proof of Stake. Dabei
geht es nicht darum, wie viel Arbeit ein Teilnehmer in das Erstellen des Blocks investiert, sondern wie
viele Anteile bzw. Einsatz der jeweilige Teilnehmer in Form der Währung innerhalb der Blockchain hält
(stake). Ein Einsatz ist ein Geldbetrag, der für einen bestimmten Zeitraum gesperrt ist. Der Vorteil
hierbei ist, dass anders als zu PoW die Währung bereits errechnet wurde und nicht noch erst erstellt
werden muss, wie es z. B. bei Bitcoin der Fall ist. Hierdurch können Ressourcen gespart werden. Jedes
Mal, wenn ein neuer Block erstellt wird, werden also eher die Teilnehmer ausgewählt einen Block zu
erstellen, welche auch einen erhöhten Anteil in der Blockchain besitzen [47].

## 8 Blockchain und Federated Learning

Durch die dezentrale Eigenschaft des Federated Learning ist die additive Verwendung einer
Blockchain, welche auch einen dezentralen Charakter aufweist, ein naheliegender Schritt. Im
Folgenden wird das Paper „A Systematic Survey of Blockchained Federated Learning“ [48] und deren
Vorstellung verschiedener Architekturen bzw. Einsatzmöglichkeit eines FL-Systems in Kombination mit
einer Blockchain ausgeführt. Dabei werden jeweils die einzelnen Vor- und Nachteile im Nachgang
beschrieben, die bei dem Einsatz der jeweiligen Architektur auftreten können und inwiefern es
sinnvoll sein kann, eine Blockchain mit einem FL-System zu verbinden.


### 8.1 Blockchain Federated Learning Architekturen

8.1.1 Fully Coupled BCFL (FuC-BCFL)
FuC-BCFL [48] definiert ein System, innerhalb dessen die Blockchain vollständig mit dem Federated
Learning verbunden ist und bei dem die Clients die Aufgabe haben, sowohl lokale Modelle trainieren
als auch Updates zu verifizieren und neue Blöcke zu generieren.

In diesem dezentralen System kann jede Node am lokalen Modelltraining und der globalen
Modellaggregation teilnehmen, wodurch die Rolle des zentralen Aggregators von der Blockchain
übernommen wird. Es gibt zwei Methoden zur Aggregation des globalen Modells: wenige ausgewählte
Nodes sammeln verifizierte lokale Modellupdates und führen dann die Aggregation durch, oder alle
Nodes nehmen an der globalen Modellaggregation teil. Die Blockchain enthält wiederum
Trainingsdaten, verifizierte lokale und globale Modellupdates bzw. aktualisierte Modellgewichte sowie
andere während des Lernprozesses erzeugte Daten und Metadaten.

_Vorteile von FuC-BCFL:_

```
● Vermeidung eines Single-Point-of-Failure
durch Dezentralisierung und Verteilung des
Systems auf alle Nodes.
```
```
● Keine Datenübertragung zu zentralen Servern,
wodurch Datenschutzverletzungen vermieden
und Kommunikationskosten reduziert werden.
```
_Nachteile von FuC-BCFL:_

```
● Höherer Bedarf an Rechenressourcen, da
sowohl Blockchain- als auch FL-Operationen
im selben Netzwerk laufen.
```
```
● Begrenzte Bandbreite in der Kommunikation
des Blockchain-Netzwerks, was zu Latenzen
führen kann.
```
8.1.2 Flexibly Coupled BCFL (FlC-BCFL)
Die FlC-BCFL-Architektur beschreibt wiederum ein flexibel gekoppeltes Blockchain- und Federated
Learning System, bei dem die Blockchain und das FL-System in getrennten Netzwerken arbeiten [48].

Die Clients des FL-Systems sind nicht die Nodes der Blockchain (Miner), wie es bei der Fully Coupled
Architektur der Fall war. In diesem System sammeln und trainieren die Clients lokale Daten, während
die Verifizierung der lokalen Modellupdates von Minern auf der Blockchain durchgeführt wird. Die
Miner können auch das globale Modell aggregieren, wodurch kein zentraler Aggregator erforderlich
ist.

Konkret sammeln die Clients lokale Daten, trainieren die Modelle und laden die Modellupdates auf der
Blockchain hoch. Die Miner auf der Blockchain führen die Verifizierung durch, und nur validierte
Updates werden für die Aktualisierung des globalen Modells verwendet. Nach der Aggregation werden
alle Daten in der Blockchain gespeichert und Belohnungen werden basierend auf den Leistungen der
Teilnehmer verteilt.

```
Abbildung 25 : Darstellung einer Fully Coupled Blockchain
Federated Learning Architecture [48].
```

##### 48

_Vorteile von FlC-BCFL:_

- FL und Blockchain laufen auf unterschiedlichen
    Netzwerken und Geräten, was den
    Kommunikationsdruck und die Latenz reduziert.
- Die Rohdaten bleiben bei den Clients, wodurch
    das Risiko von Datenlecks durch Angriffe auf das
    Blockchain-Netzwerk verringert wird.
- Blockchain ermöglicht ein effizienteres Teilen der
    Daten für FL als herkömmliche FL-Systeme.

_Nachteile von FlC-BCFL:_

- Die Verwaltung von Blockchain und FL ist
    schwierig, da sich diese stark unterscheiden.
- Single-Point-of-Failure kann auftreten, wenn ein
    zentraler Aggregator vorhanden ist.

8.1.3 Loosely Coupled BCFL (LoC-BCFL)
In der LoC-BCFL-Architektur trainieren die Clients ihre
Modelle wiederum lokal und laden die Modellupdates auf der Blockchain hoch. Miner verifizieren
diese lokalen Modellupdates und generieren eine Art Bewertungen für diese Clients. Die Miner
konkurrieren um die Erstellung eines neuen Blocks und dem Hinzufügen dieses Blocks in der
Blockchain. Anschließend sammelt der Aggregator die verifizierten Updates und führt die globale
Aggregation der Modellgewichte durch. Monetäre Belohnungen und Strafen werden basierend auf
den Bewertungen der Clients verteilt.

_Vorteile von LoC-BCFL:_

- Blockchain und FL sind vollständig unabhängig
    voneinander, was den Datenschutz verbessert.
- Die Bewertung der Akteure ermöglicht eine bessere
    Teilnehmerverwaltung, sichert die Qualität der
    Daten, verbessert die Modellgenauigkeit und
    verhindert böswillige Angriffe.

_Nachteile von LoC-BCFL:_

- Die Blockchain ist kaum in den FL-Prozess
    eingebunden und nur für Verifikation und
    Bewertung verantwortlich, daher ist das FL-Modell
    nicht wirklich dezentralisiert und Risiken wie
    Datenlecks und Single-Point-of-Failure bestehen
    weiterhin.
- Die unabhängige Wartung von Blockchain und FL führt zu
    einer ineffizienten Ressourcennutzung.

```
A b b i l d u n g 2 8 : A l s l
```
```
Abbildung 26 : Dargestellt als Alternative zu FuC-BCFL eine Flexibly
Coupled BCFL (FlC-BCFL) Architektur [48].
```
```
Abbildung 27 : Architektur des
beschriebenen LoC-BCFL-Systems [48].
```

### 8.2 Vorteile von BCFL

Wie bereits oben bei der Beschreibung verschiedene Blockchain-Architekturen [48] dargestellt wurde,
kann unter Umständen ein Single-Point-of-Failure vermieden werden, indem der eigentliche
Aggregate-Server durch das Blockchain-System ersetzt und die Aggregation der Modellgewichte
mittels der Blockchain bzw. dessen Nodes durchgeführt wird. Darüber hinaus können unzuverlässige
Einsendungen von Clients durch Verifizierungsmechanismen der Blockchain herausgefiltert werden.
Vor der Aggregation lokaler Modellgewichte zur Aktualisierung des globalen Modells können demnach
anomale Daten erkannt und nur gültige Daten für die Berechnung des globalen Modells verwendet
werden [49].

Verschiedene wirtschaftliche Anreize, wie Kryptowährungen, können ebenfalls genutzt werden, um
Clients zu einem regelkonformen Verhalten (vgl. Beschreibung des Proof-of-Concept) gemäß den
vordefinierten Regeln und Aktionen zu bewegen. Daten können zudem dauerhaft gespeichert und
effektiv auf der Blockchain geteilt werden. Sobald die Daten auf der Blockchain gespeichert sind, ist es
schwierig, diese rückwirkend zu manipulieren. Gleichzeitig können autorisierte Clients auf die
Blockchain zugreifen, um die dort gespeicherten historischen Daten abzurufen, was die Datenabfragen
wesentlich erleichtert.

### 8.3 Nachteile von BCFL

Die Verbindung einer Blockchain mit einem FL-System hat auch einige Nachteile [50].Die Integration
kann zu erhöhter Komplexität und höheren Implementierungskosten führen, da sowohl Blockchain-
als auch Federated-Learning-Technologien anspruchsvoll sind und spezielle Fachkenntnisse erfordern.
Das kann auch zu Problemen in der Zukunft führen, wenn der PoC aktiv und praktisch eingesetzt
werden soll und der Nutzende nicht über die notwendigen Fachkenntnisse verfügt, wenn diese nötig
wären.

Die Modelle enthalten viele Parameter und die Clients haben oft nur begrenzte
Kommunikationsressourcen. Dies führt zu hoher Latenz und begrenzt die Effizienz von FL-Systemen
[48]. Dieser Umstand kann durch eine zusätzliche Verwendung einer Blockchain dazu führen, dass
noch mehr Ressourcen verbraucht werden. Zudem können Methoden zur Reduzierung der
Kommunikationskosten die Modellleistung beeinträchtigen oder die Privatsphäre der Nutzer
gefährden, indem diverse Metadaten auf der Blockchain öffentlich erfasst werden.

Blockchain-basierte FL-Systeme (aber auch andere KI-Systeme) sind schlecht für Szenarien mit Non-
IID-Daten geeignet. Die Unterscheidung zwischen Non-IID und böswilligen Daten ist schwierig, was die
Generalisierbarkeit des globalen Modells ggf. beeinträchtigt. Non-IID-Daten erschweren darüber
hinaus die Konvergenz des globalen Modells, wie in den Testdurchläufen zu sehen war und erhöhen
die notwendige Anzahl der Trainingsrunden, Daten oder Clients.

Die einzelnen Vor- und Nachteile werden bei der Entwicklung des PoC berücksichtigt. So wird
beispielsweise keine Blockchain-Technologie eingesetzt, welche PoW verwendet, um das
angesprochene Problem der reduzierten Systemgeschwindigkeit zu umgehen. Darüber hinaus wird
überprüft, welche Daten innerhalb der Blockchain gespeichert werden können, die keine zu sensiblen
Informationen über die Teilnehmer veröffentlichen, welche von den anderen Teilnehmern eingesehen
werden könnten. Da es sich vorerst um einen PoC handelt, ist der Fokus auf die allgemeine
Benutzerfreundlichkeit eher reduziert, da es vorrangig um die technische Umsetzung und
Realisierbarkeit geht.


### 8.4 Warum Blockchain im Proof-of-Concept

Wie bereits in Abschnitt Blockchain und Federated Learning erwähnt, ist es durch die Ähnlichkeit in
der Architektur und ihrem dezentralen Charakter zwischen einer Blockchain und einem Federated
Learning System nachvollziehbar beide Technologien miteinander zu verbinden [48].

Es gibt bereits eine Vielzahl an wissenschaftlichen Arbeiten und Programmen, welche versuchen, eine
Blockchain-Architektur und ein Federated Learning System miteinander zu verbinden (z. B. das FL-
Framework Flower) [51].

Innerhalb der Arbeit und der Erstellung des PoC wurde sich jedoch darauf konzentriert die Blockchain
im Wesentlichen dafür zu verwenden, für was diese im Grunde auch entwickelt wurde (vgl. Einführung
Blockchain), das bedeutet Informationen rückwirkend vor Manipulation schützen zu können.

Da ein Federated Learning System darüber hinaus einen demokratischen Charakter besitzt, also
dadurch gekennzeichnet ist, dass in der Regel jeder partizipieren kann und jeder sein Teil (hier in der
Form von Modellgewichten) im System beiträgt, wird auch der allgemeine Austausch von
Informationen veröffentlicht und diesen dadurch manipulationssicher zu machen. Die Mehrheit im
System entscheidet dementsprechend, ob eine Manipulation vorliegt oder nicht und nicht ein
zentraler Server oder Instanz, wobei dadurch die einzelne Einflussnahme von jedem Akteur
eingeschränkt wird und diese so nur in ihrer Gesamtheit Einfluss nehmen können.

## 9 Technologien im Proof-of-Concept

### 9.1 Ethereum

Neben vielen entwickelten Programmiersprachen, Blockchains und Start-Ups in Bezug auf die Hyper-
Ledger-Technologie, gibt es vor allem Ethereum, welche viele Vorteile bei der Entwicklung von
sogenannten DApps bietet [52]. Das Wort DApps bezieht sich auf Decentralized-Apps, was im
Spezifischen die Entwicklung von Applikationen beschreibt, welche eine dezentrale Architektur, z. B.
eine Blockchain verwenden [53].

Eine Eigenschaft von Ethereum ist vor allem das Bereitstellen von Smart Contracts, welche es
ermöglichen, dass man programmierte Verträge erstellen kann. Diese Verträge sind Programme,
welche aufgerufen und automatisch ausgeführt werden, sobald eine bestimmte Bedingung erfüllt
wurde.

Als ein Beispiel für ein Szenario in welchem Smart Contracts verwendet werden wird angenommen,
dass Herr A. der Frau B. 10€ für ein gekauftes Fahrrad schuldet. So kann vorab innerhalb des Vertrags
die jeweils einzelnen Parteien festgelegt werden (Herr A. und Frau B.) und unter welchen Bedingungen
die 10€ automatisch an die Frau B. überwiesen werden sollen. Sobald der Übergang des Fahrrads von
der Applikation erfasst wurde, werden die 10€ demnach automatisch an die Frau B. übertragen, wobei
innerhalb von Ethereum hierfür eine eigene Währung Ether existiert.

Diese Art automatisierte Verträge zu schließen, bietet viele reale Einsatzmöglichkeiten z. B. im
rechtlichen Bereich, bei notariellen Beurkundungen und Wahlsysteme im politischen Zusammenhang.

Da Python vorab als Programmiersprache für den PoC ausgewählt wurde (vgl. Python), war es wichtig,
einen passenden Blockchain-Anbieter auszuwählen, welcher es ermöglicht, mittels Python in einer
Schnittstelle zu interagieren. Ethereum bzw. dessen Smart Contracts werden anhand der
Programmiersprache Solidity erstellt. Es ist jedoch möglich, diese Smart Contracts anhand einer
Schnittstelle in einer Python-Umgebung auszuführen.


### 9.2 Ganache

Da für die Entwicklung vorrangig lokal auf einem Gerät durchgeführt wird, ist es nötig eine lokale
Blockchain-Simulation auf diesem abzubilden, um Smart-Contracts zu testen, zu debuggen und zu
implementieren, ohne auf das echte Ethereum-Netzwerk zugreifen zu müssen, wobei auch echte
Geldtransaktionen durchgeführt werden.

Dabei emuliert (nachahmt oder imitiert)
Ganache eine Ethereum-Blockchain
vollständig und ermöglicht es
Testtransaktionen durchzuführen, welche
zwar nicht mit der echten Währung Ether
bezahlt werden, jedoch aber die realen
Bedingungen simuliert [54]. Darüber hinaus
ist Ganache ausführlich dokumentiert und
die Bedienung benutzerfreundlich, wie auf
der Darstellung der GUI von Ganache
einzusehen (siehe Abb. 29).

### 9.3 Python

Es standen für das Erstellen des PoC einige Programmiersprachen zur Auswahl, jedoch zeichnete es
sich schnell ab, dass entweder die Programmiersprache Python oder C++ in die engere Auswahl mit
einbezogen werden.

Dies hatte mehrere Gründe. Einerseits ist C++ eine sehr effiziente Programmiersprache, welche es
einem erlaubt, auf einem low-level dementsprechende Programme zu entwickeln. Viele Blockchain-
Applikationen wurden ebenfalls mit C++ entwickelt, u.a. auch Bitcoin [55].

Da die Arbeit/PoC jedoch auch einen nicht unerheblichen Anteil an Machine/Deep-Learning umfasst,
war auf der anderen Seite Python [56] durchaus sinnvoll einzusetzen, da ein Großteil der benötigten
Libraries mittels Python erstellt wurden. Der Grund, wieso sich für Python entschieden wurde, ist die
Einsetzbarkeit vieler Libraries in Kryptografie, Entwicklung von Sockets und ML/DL, welche gute bis
sehr gute Möglichkeiten bieten, um mit den entsprechenden Modulen den geplanten PoC zu
entwickeln. Letztendlich bietet Python von allen Programmiersprachen den besten Kompromiss an die
Anforderungen des geplanten PoC.

#### 9.3.1 Tensorflow

Tensorflow [57] ist neben PyTorch eine der wichtigsten Open-Source-Bibliotheken, was die
Entwicklung von Machine und Deep Learning betrifft. Ein Vorteil der Library ist es vor allem, dass diese
verteiltes Training unterstützt und es ermöglicht, komplexe Modelle auf verschiedenen Geräten zu
trainieren, was essenziell für Federated Learning ist. Tensorflow bietet zusätzlich umfassende
Bibliotheken und Werkzeuge zur Modellbewertung, Optimierung und Implementierung, die die
Entwicklung und Bereitstellung von Federated Learning Algorithmen beschleunigen.

#### 9.3.2 Python Sockets

Python Sockets [58] sind eine weitere entscheidende Komponente im PoC, da sie die
Netzwerkkommunikation zwischen verschiedenen Geräten und Servern ermöglichen. In einer
Federated Learning Umgebung müssen die Modellgewichte und andere Daten sicher und effizient
ausgetauscht werden können. Python Sockets bieten eine flexible und leistungsstarke Methode zur
Implementierung dieser Kommunikationsprotokolle, um Daten zwischen den verschiedenen
Teilnehmern der Blockchain zu übertragen. Dabei ist es vor allem wichtig, dass man noch über einen
gewissen Grad an Anpassbarkeit der einzelnen Sockets verfügt, um diese an die Gegebenheiten in
Hinblick auf den PoC individuell einzustellen und anzupassen.

```
Abbildung 28 : Oben abgebildet die grafische Oberfläche des Programms
Ganache, welches auch im PoC eingesetzt wird [Quelle: Eigene Darstellung].
```

## 10 Proof of Concept

Code des Proof-of-Concept: https://github.com/Mvb-DL/SickurityFLee.git

_Disclaimer_
Der Großteil der Umsetzung des PoC ist aus eigener geistiger Schöpfung (zu Teilen auch inspiriert
durch Aspekte der Rechtswissenschaft und Spieltheorie) entstanden. Es konnte sich wenig an
alternativen Entwicklungen orientiert werden, da es im Bereich Federated Learning unter dem Aspekt
der Cybersicherheit verhältnismäßig wenige praktische Umsetzungen bzw. Prototypen gibt [59].

Daher schien es interessant unter der Zuhilfenahme von bereits bewährten Sicherheitsmechanismen
wie Hashing, Advanced Encryption Standard usw. in Verbindung mit neuartigen Methoden, einen PoC
zu fertigen, welcher verschiedene neue Ansätze und Ideen vereint und ausprobiert.

### 10.1 Beschreibung des Proof-of-Concept

In Abschnitt Blockchain Federated Learning Architekturen wurde bereits beschrieben, über welche
Architekturen ein FL-System verfügen kann. Der zu beschreibende PoC vereint eine Kombination aus
einem horizontalen und cross-device FL-System.

Das FL-System hat insofern eine horizontale Architektur, da die Datensätze der Clients über die
gleichen Merkmale, aber unterschiedliche Beispielinstanzen verfügen. Das bedeutet z. B. bei der
Klassifikation von Brustkrebs, dass ein Binäres Klassifikationsmodell innerhalb des Systems verwendet
wird, wobei die Labels des Datensatzes „Brustkrebs“ und „kein Brustkrebs“ umfassen. So sind die
Merkmale gleich, jedoch die eigentlichen Bilder bzw. Beispielinstanzen, welche harmlose Bilder und
Bilder von Brustkrebs beinhalten, unterschiedlich.

Bei der Testdurchführung und der Entwicklung handelt es sich aktuell aber noch um ein vertikales FL-
System, da für die allgemeinen Testzwecke der multiklassen-MNIST-Datensatz von allen Teilnehmern
verwendet wird und bei der Durchführung des Angriffs eines Clients nur die Merkmale (Labels)
vertauscht werden. Nach Abschluss der Testphase wird der PoC dann für ein horizontales FL-System
eingesetzt. Das heißt, das vertikale FL-System wird in ein horizontales FL-System transformiert.

Des Weiteren verfügt das FL-System über eine Cross-Device-Architektur, da der PoC in der Praxis für
diverse Einrichtungen eingesetzt werden soll, welche sich hinsichtlich der Daten, der
Einrichtungsgröße und Sicherheitsvorkehrungen stark unterscheiden. Demnach muss das System bzw.
der PoC robust genug entwickelt werden, um eine möglichst breite Schnittstelle an Geräten
abzudecken.

Da primär vor allem Computer und weniger IoT- oder mobile Endgeräte berücksichtigt werden, ist die
Herausforderung, eine passende Schnittstelle zu entwickeln, etwas geringer. Jedoch muss auf lange
Sicht der PoC an die individuellen Bedürfnisse des jeweiligen Clients bzw. der jeweiligen Einrichtung
angepasst werden. Dies bedeutet konkret die Kompatibilität mit verschiedenen Betriebssystemen,
Machine - und Deep Learning Algorithmen, sowie unterschiedlichen Frameworks bei der
Implementierung derartiger Algorithmen (in Python z. B. Tensorflow, PyTorch etc.).

Auch muss der PoC die vom Client eingegebenen Daten verarbeiten und aufbereiten, damit diese
innerhalb des Systems auch korrekt verwertet werden können. Es ist also eine gewisse Flexibilität und
Anpassbarkeit notwendig.

Die folgende Beschreibung vermittelt einen groben Überblick über den Aufbau und die Struktur des
PoC. Eine Beschreibung im Detail findet sich indes in Abschnitt PoC-Aufbau und System-Ablauf.

Im System gibt es drei Akteure (vgl. Topologie und Struktur - Proof of Concept): Die Clients, der
Aggregate-Server und der Gateway-Server.


Das System startet immer mit dem Gateway-Server und dem Registrierungsprozess, innerhalb dessen
die Daten (IP-Adresse, Public-Key etc.) erfasst werden. Dann erfolgt die Registrierung des Aggregate-
Servers und die Bereitstellung des globalen ML/DL-Modells. Es folgt der Client, welcher durch den
Gateway-Server registriert und dann anschließend durch den Aggregate-Server validiert wird.

Das System ist rundenbasiert. Eine Runde wird durch den Beginn des lokalen Trainings des Clients
gestartet und mit dem Übermitteln der aggregierten Modellgewichte aller Clients im System durch
den Aggregate-Server an die Clients beendet.

Dabei kann das einzelne lokale Training des Clients wiederum viele Epochen umfassen, eine
Trainingsrunde umfasst demnach immer mindestens eine Trainings-Epoche pro Client.

Der Gateway-Server dient als eine Vermittlungsinstanz und sorgt dafür, dass die einzelnen Akteure
den Registrierungsprozess durchlaufen müssen, so dass sie eindeutig identifiziert und authentifiziert
sind. Dieser Registrierungsprozess umfasst dabei wiederum verschiedene Aspekte:

Nach Anfrage des Aggregate-Servers oder des Clients, müssen diese diverse Daten, wie IP-Adresse etc.
an den Gateway-Server senden. Diese Daten werden intern über eine Black- und Whitelist überprüft.
Das bedeutet, dass IP-Adressen, welche zuvor schon gesperrt worden sind, nicht am System
partizipieren können. Das Blacklisting ist im aktuellen PoC noch nicht aktiv implementiert. Nach
erfolgter Anmeldung wird durch den Gateway-Server ein Smart Contract aufgesetzt, welcher
wiederum Folgendes beinhaltet:

Der Vertrag kennzeichnet eindeutig um welchen Akteur es sich handelt und fordert von diesem Akteur
eine gewisse Summe als Kaution in Ether ein. Diese Kaution dient dazu, dass bei einem nachweislichen
Fehlverhalten des Akteurs (Daten oder Modell Manipulation) der Betrag einbehalten wird. Dies erhöht
die Motivation der Partizipierenden, den Regeln im System Folge zu leisten. Auch der Gateway-Server
muss zuvor eine derartige Kaution überweisen. Wurde der Vertrag erstellt und die Kaution
übermittelt, ist es die Aufgabe des Gateway-Servers, den jeweiligen Akteur freizugeben, die Daten in
die Blockchain einzupflegen und den Vertrag an den registrierten Akteur zu übersenden.

Der Aggregate-Server ist der zweite System-Akteur und ist nach der Registrierung für das globale
ML/DL-Modell und die Aggregation der einzelnen Client Modellgewichte zuständig. Auch hat der
Aggregate-Server Einfluss darauf, wann das System bzw. die einzelnen Trainingsrunden beendet
werden.

Der Client als dritter Akteur muss sich ebenfalls über den Gateway-Server registrieren. Nachdem der
Client zusätzlich durch den Aggregate-Server validiert wurde (der Aggregate-Server überprüft die
Daten in der Blockchain mit den übermittelten Daten des Clients), erhält dieser das ML/DL-Modell und
trainiert lokal mit seinen Trainingsdaten. Parallel trainiert der Aggregate-Server ebenfalls mit dem
gleichen Modell eigene Testdaten. Die Ergebnisse beider Akteure werden daraufhin in Hinblick auf die
Daten und die Resultate der einzelnen Modelle miteinander verglichen. Bei diversen Abweichungen
wird der Client präventiv ausgeschlossen, auf die Blacklist gesetzt und der Client kann nicht mehr am
System teilnehmen (Näheres hierzu siehe Client Validierung).

Das Ergebnis in Form der Modellgewichte wird dann in der Blockchain als Hash hochgeladen. Der
Client erhält durch den Aggregate-Server am Ende jeder Runde die aggregierten globalen
Modellgewichte und ersetzt die vorherigen Modellgewichte durch diese neuen erfassten Gewichte.

Beide Akteure kontrollieren immer parallel, welche Daten empfangen und welche Daten ursprünglich
in der Blockchain hochgeladen wurden, um Manipulationen, die von externen Dritten auf dem
Kommunikationsweg durchgeführt wurden, ausschließen zu können.

Im Allgemeinen basiert das System auf der Grundlage, dass jegliche Aktion grundsätzlich verboten ist,
es sei denn, es gibt einen Erlaubnisvorbehalt. Das bedeutet, dass jeder Teilnehmer grundsätzlich als


kritische und unsichere Entität betrachtet wird. Jedoch besteht primär das Gefahrenpotential eines
Missbrauchs bzw. Manipulation durch die Clients und externe Akteure im System.

So ist es Ziel des Systems, jede Aktion eines Akteurs bis zu einem vertretbaren Grad (vertretbar
bedeutet hier, so viele Daten veröffentlichen zu können, ohne ein Sicherheitsrisiko darzustellen)
öffentlich zugänglich zu machen, um im Nachgang kausal nachweisen zu können, welche Aktion zu
welchem Ergebnis im System beigetragen hat. Falls ein Regelbruch nachgewiesen wird, der kausal mit
einer verbotenen Aktion in Zusammenhang steht, kann ein Teil der Kaution des vermeintlichen
Angreifers im System einbehalten werden oder der Angreifer wird vollständig aus dem System
ausgeschlossen, ohne seine Kaution zurückgezahlt zu bekommen.

Dies führt jedoch zu dem Problem, dass ein Systemexterner mit Absicht das System sabotiert und die
Haftung ungerechterweise auf einen Akteur fällt bzw. der Akteur unverschuldet haftbar gemacht wird.
Um unter anderem auch diesem Aspekt entgegenzuwirken, müssen folgende Regeln im System
erreicht und berücksichtigt werden:

```
● Im System gibt es festgelegte/legale Aktionen. Andere Aktionen als die festgelegten dürfen
nicht durchgeführt werden. Verbot mit Erlaubnisvorbehalt.
```
```
● Es ist die Art und der Inhalt einer Aktion von jedem Akteur bis zu einem notwendigen Grad im
System einsehbar. Hierdurch kann eindeutig die Verantwortlichkeit nachvollzogen und auch
rückwirkend in der Blockchain überprüft werden.
```
```
● Alle internen Daten und Informationen der Akteure werden prinzipiell, bis auf wenige
notwendige Ausnahmen, nicht geteilt. Notwendige Ausnahmen sind der Public-Key des
Akteurs, der Hash des ML/DL-Modells, der Hash der lokalen Client Modellgewichte, der Hash
der globalen Modellgewichte, die URL des Akteurs und die Rolle des Akteurs.
```
```
● Durch die geteilten Informationen der Akteure, darf man nicht auf die restlichen i.d.R.
privaten Informationen der Akteure schließen können.
```
```
Abbildung 29 : Wie in der Grafik zu sehen befinden sich die registrierten Akteure in einem Rahmen,
in dem nur legale Aktionen vollzogen werden dürfen. So werden die Verantwortlichkeiten klar
Internen und Externen zugeordnet [Quelle: Eigene Darstellung].
```

```
● Der Zugriff und die Manipulation durch Systemexterne bzw. Dritte können nie vollständig
ausgeschlossen werden.
```
```
● Jeder Akteur soll zu jedem Zeitpunkt nachvollziehen können, welche Aktionen andere Akteure
durchgeführt haben.
```
```
● Jede Aktion muss eindeutig einem Akteur zugeordnet werden können, um diesen haftbar für
seine Aktion zu machen. Das bedeutet, jeder Akteur muss seine Aktion kennzeichnen und ist
ab diesem Zeitpunkt haftbar. Kann man eine Aktion nicht einem Akteur zuordnen, so ist der
Akteur auch nicht haftbar.
```
```
● Ist kein Akteur haftbar zu machen, so wird kein Akteur bestraft.
```
### 10.2 Funktionale und nicht-funktionale Anforderungen des Proof of Concept

Der PoC umfasst noch weitere funktionale und
nicht funktionale Anforderungen [60]. Die
wesentlichen Ziele lassen sich nachfolgenden
Punkten der Reihenfolge nach, anhand von nicht-
funktionalen Anforderungen auflisten.

1. Sicherheit
2. Zuverlässigkeit
3. Leistung
4. Skalierbarkeit
5. Kompatibilität
6. Benutzerfreundlichkeit

Vorab muss eine Einschränkung des PoC beachtet
werden, da Manipulationen der Trainingsdaten,
falls diese vor der Registrierung im System geschehen, nicht verhindert werden können. Sobald der
Client mit seinen Trainingsdaten jedoch registriert wurde, werden die Aktionen der einzelnen Akteure
getrackt und es wird versucht rückwirkend Anomalien aufzudecken und bösartige Aktionen
auszusortieren.

Als reales Vorbild wurde der Vorgang einem polizeilichen Ermittlungsverfahren nachempfunden. Es
werden über die Zeit Beweise gesammelt und sobald eine gewisse Beweisbarkeit über die Haftbarkeit
vorliegt, wird der jeweilig Betroffene damit konfrontiert und mit einer Strafe versehen (in diesem Fall
monetär mittels einer Kaution) [61].

Da der Zugriff externer Dritter - wie bereits erwähnt - in einem System nie ausgeschlossen werden
kann, ist es Ziel im Umkehrschluss nachzuweisen, was die aktiven Akteure innerhalb des Systems
durchführen, um dann die Verantwortlichkeiten genau zuzuordnen und abzugrenzen. Sobald ein
Dritter das System manipuliert und den aktiven Akteuren keine Teil- oder Mitschuld zugeordnet
werden kann, werden diese auch nicht bestraft.

Dieses Vorgehen ist hinsichtlich der Performance und Skalierbarkeit des Systems nicht zwingend die
effizienteste Methode, jedoch wird die Datenintegrität und die Authentizität der Akteure bzw.
Sicherheit als oberste Priorität innerhalb des PoC betrachtet.

```
Abbildung 30 : Im nachfolgenden Netzdiagramm sind die
Ausprägungswerte der nicht-funktionalen Anforderungen des PoC
nochmals übersichtsartig dargestellt [Quelle: Eigene Darstellung].
```

#### 10.2.1 Sicherheit

Die Anforderung hinsichtlich der Sicherheit umfasst im Spezifischen die Punkte Datenintegrität und
Authentizität, Logging und Profiling, sowie die Akteure zu identifizieren und zu authentifizieren.

Da es sich um einen PoC handelt, ist die Priorisierung der Performance und Effizienz des Systems
vorerst nach hinten gestellt worden und es wird sich primär auf die Systemsicherheit fokussiert.

_Datenintegrität und Authentizität_

Datenintegrität bedeutet, dass die Daten, welche innerhalb des Systems verwendet werden, während
der Speicherung, Übertragung und Verarbeitung unverändert und vollständig bleiben [62]. Dies ist vor
allem beim ML/DL-Modell und den einzelnen Modellgewichten wichtig.

Authentizität bezieht sich im System wiederum darauf, dass sowohl die Sender und Empfänger als
auch die Inhalte von Daten und Kommunikation authentisch und vertrauenswürdig sind. Beteiligte
Akteure müssen verifiziert sein, um am System zu partizipieren und werden dahingehend auch einer
Prüfung unterzogen. So können nur authentifizierte Akteure verschlüsselt miteinander kommunizieren
[62].

Die beschriebene Datenintegrität kann beispielsweise durch das Hashing im Verbund mit der
Blockchain gewährleistet werden (vgl. Einführung Blockchain), darüber hinaus kann das Public-Private-
Key Verfahren und das Verwenden digitaler Zertifikate für die Authentifizierung der einzelnen Akteure
genutzt werden (vgl. Public-Private-Key Verfahren).

_Logging und Profiling_

Um die zuvor beschriebenen Verantwortlichkeiten den einzelnen Akteuren zuordnen zu können, ist es
notwendig die einzelnen Aktionen und Datenübertragungen dieser Akteure zu dokumentieren und im
Anschluss nachvollziehbar darzustellen. Diese Aufgabe wird vor allem von der Blockchain
übernommen. Dabei dient die Blockchain wie ein externes Logbuch, dessen Einträge nicht verändert
werden können und jeder Teilnehmer das Recht hat dieses Logbuch einzusehen [46].

Dieses Logging-Prinzip soll einerseits einen ausreichenden Datenschutz der Teilnehmer gewährleisten,
andererseits die Robustheit des Systems nicht dadurch zu gefährden, zu viele Daten über die Akteure
preiszugeben.

_Akteure identifizieren und authentifizieren_

Um die Akteure identifizieren zu können, ist es notwendig, dass diese einzelne Registrierungsschritte
durchlaufen werden. Dabei ist primär der Client und der Aggregate-Server wichtig zu identifizieren, da
der Gateway-Server vor dem Start des Systems bereits identifiziert sein muss.

Es gibt verschiedene Ansätze, inwieweit die Akteure im PoC identifiziert werden könnten. Einerseits
über verschiedene personenbezogene Daten oder einem aufwändigen Prozess, bei welchem der
entsprechende Client eindeutig registriert wird, um bösartige Teilnehmer ausschließen zu können.
Diese Anforderung wird bei der Umsetzung des PoC jedoch nicht näher betrachtet, da anhand der
Verwendung von Python Sockets der Anmeldeprozess anders implementiert wurde und bei einer
möglicherweise späteren Umsetzung des Prototyps hin zu einer Web-App, das Erstellen eines
aufwändigen Anmeldeprozesses wesentlich sinnvoller ist.


#### 10.2.2 Zuverlässigkeit

Eine geringe Fehleranfälligkeit beschreibt den Umstand, falls innerhalb des PoC-Systems
unvorhersehbare Aktionen durch die Akteure oder Dritte durchgeführt werden, diese Aktionen nicht
zu einem Versagen, zu einer Fehlausführung oder Beenden des Systems führen können.

Eine derartige Fehleranfälligkeit kann dementsprechend auch als Angriffsfläche dienen, da gezielt das
System gestört und behindert werden soll (vgl. Denial of Service Attacks in Federated Learning). Um
dies zu verhindern, muss verstärkt auf Errors and Exceptions [63] im System geachtet werden, um
eben solche Vorfälle präventiv abzufangen und zu verarbeiten.

Hierfür ist auch der Ansatz der einzelnen Aktionen unter dem Gesichtspunkt Verbot mit
Erlaubnisvorbehalt angedacht. Es können nur geplante Schritte der einzelnen Akteure durchgeführt
werden und so kann einer Überlastung gezielt entgegengesteuert werden.

#### 10.2.3 Leistung (Effizienz und Latenz)

Wie bereits erwähnt, liegt das Hauptaugenmerk des PoC auf Sicherheit und Zuverlässigkeit, welches in
einem System oft auch zu Lasten der Performance gehen kann. Jedoch sollte darauf geachtet werden,
dass das System eine ausreichende Leistung und geringe Latenz (Zeit zwischen Anfrage und
Rückmeldung des Systems) aufweist [64]. Wobei hier zeitlich angemessene Relationen erst im
Nachgang mit einem gewissen Erfahrungswert definiert werden können.

#### 10.2.4 Skalierbarkeit

Der PoC soll vorrangig für Umgebungen entwickelt werden, in denen vor allem die Sicherheit und
nicht die Skalierbarkeit sowie Effizienz von entscheidender Bedeutung sind (vgl. Einsatzgebiete,
Szenarien und Möglichkeiten des Proof-of-Concept). Dies umfasst zum Beispiel mehrere
Krankenhäuser oder vergleichbare medizinische Einrichtungen als Clients. Es wird in dieser Umgebung
z. B. ein Modell verwendet, welches verschiedene Typen an Brustkrebs erkennen soll. Die
verschiedenen medizinischen Einrichtungen trainieren zusammen ein globales Modell, um gegenseitig
von ihren Daten zu profitieren, jedoch ohne, dass die einzelnen sensitiven, personenbezogene Daten
innerhalb des Systems veröffentlicht werden.

Dabei wird davon ausgegangen, dass die zeitliche Komponente bzw. die zeitliche Geschwindigkeit des
Systems in einem derartigen Szenario wesentlich unwichtiger ist als die Stabilität und Verlässlichkeit
dieses Systems, da eine medizinische Fehleinschätzung gefährliche und unvorhersehbare
Konsequenzen (z. B. durch getroffene Fehldiagnosen) mit sich führt.

#### 10.2.5 Kompatibilität

Der PoC wird in der anfänglichen Entwicklung eher inkompatibel einsetzbar sein und erfordert interne
Kenntnisse über Programmieren, Federated Learning und Blockchain, um den PoC an seine
individuellen Anforderungen anpassen zu können (siehe 8. Benutzerfreundlichkeit).

So wurde der PoC bzw. dessen ML/DL-Modelle mittels des Frameworks Tensorflow erstellt. Eine
Anpassung des PoC an z. B. PyTorch-Modelle ist vorerst nicht geplant. Auch kann es unter anderem zu
diversen Kompatibilitätsproblemen hinsichtlich des Betriebssystems kommen. Der vorliegende
Prototyp ist für ein Windows Betriebssystem erstellt worden. Optimierungen dieser nicht-funktionalen
Anforderung sind auf den Zeitpunkt angedacht, an welchem das System ausreichend an Stabilität,
Sicherheit und Leistung erreicht hat, um dementsprechende Testdurchführungen kompatibel auch in
anderen Testumgebungen durchführen zu können.


#### 10.2.6 Benutzerfreundlichkeit

Die nicht-funktionale Anforderung Benutzerfreundlichkeit wurde am geringsten priorisiert. Auch wenn
es hinsichtlich der Sicherheit später äußerst wichtig sein wird, dass der PoC in seiner angedachten
Umgebung auch korrekt bedient wird, um so menschliche Fehler zu reduzieren, so ist eine zu
aufwändig gestaltete Bedienoberfläche für die Durchführung von Tests etc. nicht zielführend.
Dementsprechend wird der PoC hauptsächlich durch das Starten des Python-Scripts mittels der
Command Line ausgeführt. Für den Client wurde trotzdem eine anfängliche GUI implementiert (siehe
Abb. 32 ).

### 10.3 Einsatzgebiete, Szenarien und Möglichkeiten des Proof-of-Concept

Wie bereits erwähnt, ist der PoC vorrangig für Umgebungen in den medizinischen oder anderen
ähnlichen Sektoren vorgesehen (z. B. militärische Einrichtungen, Finanzwesen), in welchen vor allem
sensible Daten verarbeitet werden.

Dementsprechend sind auch die Ziele und Eigenschaften des PoC an derartige Anforderungen
angepasst. Das bedeutet also vor allem für Einsatzgebiete, in denen Sicherheit, Systemstabilität und
Fehlerresistenz eine zentrale Rolle spielen.

Für die nähere und folgende Beschreibung soll für den PoC ein Szenario aufgezeigt werden, in
welchem der Prototyp eingesetzt werden könnte. Dies führt einerseits zu einem besseren Verständnis
des Programms bzw. des PoC, andererseits hilft es zusätzlich die Aktionen und den Ablauf der
einzelnen Akteure später besser nachzuvollziehen.

#### 10.3.1 Beispielszenario medizinische Einrichtung

In dem vorliegenden Szenario gibt es eine Vielzahl verschiedener Krankenhäuser, die große Mengen
von Bildern als Datensätze mit Hautmerkmalen gesammelt haben.

Die Datensätze umfassen zwei Klassen (binäre Klassifizierung) und wurden mit den entsprechenden
zwei Labels aufgeteilt. Das erste Label ist _kein Hautkrebs,_ das zweite Label ist _Hautkrebs_.

Da es in der Regel datenschutzrechtlich bedenklich und wirtschaftlich schädigend für ein
Unternehmen oder Einrichtung ist, ihre Daten öffentlich zu teilen, fehlt in vielen Gebieten die
notwendige Datenmenge, um die entsprechenden Algorithmen trainieren zu können [65]. Diese
Algorithmen leisten jedoch eine wesentlich bessere Performance in Hinblick auf ihre Aussagekraft
bzw. Model Accuracy, umso größer die Menge des Datensatzes ist [13].

```
Abbildung 31 : Hier zu sehen eine
vereinfachte GUI, welche für den Client
innerhalb des PoC für die Registrierung
verwendet wird. Die GUI wurde mithilfe
der Tkinter-Library in Python erstellt
[Quelle: Eigene Darstellung].
```

Da in unserem Szenario die eigentlichen Daten unter Verwendung des PoC nie das Endgerät bzw. in
unserem Fall das Krankenhaus verlassen, werden der Datenschutz und die wirtschaftlichen Interessen
nicht notwendigerweise eingeschränkt.

Die einzelnen Krankenhäuser registrieren sich mit dem PoC und werden mittels der Blockchain erfasst
und gespeichert. Nachdem genügend Daten von verschiedenen Krankenhäusern gesammelt und
deren Daten validiert wurden, werden die Daten aggregiert (vgl. Einführung Federated Learning). Das
Ergebnis wird im Anschluss wieder an die einzelnen Krankenhäuser zurückgegeben.

So profitieren die teilnehmenden Einrichtungen durch das Teilen ihrer Modelldaten, ohne
zwingenderweise gegen geltende Rechte oder ähnliche Faktoren zu verstoßen.

In den folgenden Abschnitten wird der PoC technisch und begrifflich noch einmal ausführlicher
beschrieben und dargestellt.

## 11 Topologie und Struktur - Proof of Concept

Innerhalb des folgenden Abschnitts wird die bereits ausgeführte Beschreibung des PoC noch einmal
erweitert, indem die einzelnen verwendeten Begriffe und Bestandteile näher definiert und

#### beschrieben werden.

#### 11.1 Gateway-Server

Die Funktion des Gateway-Servers besteht in der Rolle des Vermittlers zwischen dem Aggregate-
Server und den Clients. Innerhalb einer jeden Umgebung existiert stets lediglich ein Gateway-Server.
Innerhalb des Systems verfügt der Gateway-Server über die umfassendsten Zugriffs- und
Nutzungsrechte aller involvierten Akteure. In der Regel erfolgt die gesamte Kommunikation zwischen
Client und Aggregate-Server über die Zwischeninstanz des Gateway-Servers.

Die Hauptaufgaben des Gateway-Servers sind:

```
● Registrierung der einzelnen Akteure in der Blockchain.
● Validierung der versendeten Daten, wie ML/DL-Modell und Modellgewichte etc.
```
```
Abbildung 32 : Die einzelnen Krankenhäuser
(Clients) übermitteln dem PoC die jeweiligen
Modellgewichte und empfangen die aggregierten
Ergebnisse. Der Clientside PoC beschreibt lediglich
die Programmschnittstelle des Clients. Diese ist
einerseits für die Verbindung zum PoC zuständig
und übernimmt andererseits die Übermittlung
sowie die Verarbeitung von Anfragen. [Quelle:
Eigene Darstellung].
```

#### 11.2 Aggregate-Server

Die Funktion des Aggregate-Servers besteht in der Aggregation der Modellgewichte sowie der
Bereitstellung des ML/DL-Modells für die Clients. Nach erfolgter Registrierung durch den Gateway-
Server übermittelt der Aggregate-Server das ML/DL-Modell an den Gateway-Server und wartet
anschließend auf eine Verbindungsanfrage durch den Client. Im Anschluss an die Registrierung des
Clients durch den Gateway-Server erfolgt eine Prüfung des Clients durch den Aggregate-Server, um
festzustellen, ob der Client über vergiftete Daten verfügt oder anderweitig bösartig ist (vgl. Client
Validierung). Im Anschluss an die Aggregation der Client-Modellgewichte erfolgt eine Speicherung
dieser Gewichte auf dem Aggregate-Server (vgl. Federated Averaging Algorithmus). Das Ergebnis wird
schließlich in die Blockchain hochgeladen.

Die Hauptaufgaben des Aggregate-Servers sind:

```
● Bereitstellen des ML/DL-Modells
● Validierung der Clients (vgl. Client Validierung)
● Aggregieren der Client Modellgewichte (vgl. Federated Averaging Algorithmus)
● Beenden der Trainingsrunde
```
#### 11.3 Client

Der Client kann als "Arbeiter" innerhalb des Systems bezeichnet werden. Nach erfolgreicher
Registrierung des Clients auf dem Gateway-Server wird diesem das im System verwendete ML/DL-
Modell übermittelt. Im Anschluss erfolgt die bereits skizzierte Validierung durch den Aggregate-Server.
Im Falle eines erfolgreichen Testdurchlaufs initiiert der Client den lokalen Prozess der Einspeisung von
Trainingsdaten in das ML/DL-Modell. Das Resultat wird im Anschluss in die Blockchain hochgeladen.
Sobald alle Client-Modellgewichte durch den Aggregate-Server aggregiert wurden, erfolgt eine
Aktualisierung der lokalen Client-Modellgewichte durch die neuen, globalen Modellgewichte des
Aggregate-Servers.

Die Hauptaufgaben des Clients sind:

```
● Lokale Training anhand der Trainingsdaten und des globalen ML/DL-Modells
● Bereitstellen der lokalen Modellgewichte
● Updaten der lokalen Modellgewichte durch die aggregierten globalen Modellgewichte
```
#### 11.4 Smart Contract

Jeder Akteur wird eindeutig mit einem Smart Contract verifiziert. Der Akteur muss eine Kaution
einlegen, welche einbehalten wird, falls dem Akteur ein Fehlverhalten, wie Datenmanipulation
nachgewiesen werden kann. Des Weiteren werden die Modellgewichte des Clients über den Smart
Contract in die Blockchain hochgeladen [66]. Dies beinhaltet auch die globalen Modellgewichte des
Aggregate-Servers.

Unter folgendem Link ist der Code für die Smart Contracts in Solidity hinterlegt:

https://github.com/Mvb-DL/SickurityFLee/blob/main/SmartContract/Test.sol

#### 11.5 Daten, Preprocessing und Non-IID

Für die Testdurchläufe anhand des Basis Set-Up (vgl. Ermittlung des Basis Set-Up), sowie den
Testläufen mit dem PoC (vgl. Evaluation und Ergebnisse des Proof-of-Concept) wurde der MNIST-
Datensatz aus mehreren Gründen verwendet. Einerseits wurden anhand des MNIST - und CIFAR- 10 -
Datensatzes schon eine Vielzahl an Experimenten in verschiedenen wissenschaftlichen Arbeiten in


Bezug auf Federated Learning etc. durchgeführt (siehe z. B. [30], [31], [32]). Andererseits kann der
Datensatz für eine Multiklassen-Bildklassifikation eingesetzt werden und ermöglicht eine breite
Anwendung. Da es sich ebenfalls um einen Bilddatensatz handelt, kann ein Transfer zu dem zuvor
beschriebenen Einsatzszenario (vgl. Beispielszenario medizinische Einrichtung) hergestellt werden.

Der MNIST-Datensatz besteht aus 60.000 Trainingsbildern, sowie 10.000 Testbildern, welche jeweils
handgeschriebene Zahlen von 0 bis 9 darstellen (siehe Abb. 34) [67]. Diese Zahlen sind
dementsprechend mit den einzelnen Nummern gelabelt.

Da sich die Daten auf dem Endgerät des Clients befinden, entziehen sich diese dem Zugriff einer
zentralen Instanz, welche die Daten für das Modell vorbereitet (Data-Preprocessing). Daher sind die
Daten der Clients hinsichtlich ihrer Klassen meistens unterschiedlich aufgeteilt und deren Qualität
daher oft unterschiedlich. Die Daten werden so heterogen und Non-IID [11].

Heterogene Daten sind im Gegensatz zu homogenen Daten unterschiedlich in ihrer Verteilung (z. B.
hat nicht jede Klasse gleich viele Samples wie eine andere Klasse) und auch die einzelnen Merkmale
können sich unterscheiden. Wie in Einsatzgebiete, Szenarien und Möglichkeiten des Proof-of-Concept
noch beschrieben wird, kann dieser Umstand in der Umsetzung des PoC außerhalb einer
experimentellen Umgebung schnell zu einem instabilen System führen.

Non-IID Daten bedeutet wiederum, dass die Daten einerseits nicht unabhängig und andererseits nicht
identisch verteilt sind.

1. Nicht unabhängig (Non-I):

```
In einem Datensatz kann es passieren, dass die einzelnen Daten nicht unabhängig
voneinander sind (siehe Abb. 35). Das bedeutet zum Beispiel, dass der Datenpunkt A den Wert
von Datenpunkt B beeinflusst. Dies ist vor allem bei Daten, welche Zeitreihen abbilden, der
Fall. So können in einem Krankenhaus die einzelnen Krankheitsverläufe der Patienten
dokumentiert und anhand der Daten erfasst werden. Werden diese Daten anschließend
jedoch von einem Algorithmus verarbeitet, kann dies zu Performance Problemen führen, da
die meisten Algorithmen, welche auf statistischen Verfahren beruhen, meist unter der
Annahme von statistischer Unabhängigkeit funktionieren [11].
```
```
Abbildung 33 : Jeweils ein Ausschnitte/Samples aus dem MNIST-Datensatz mit
zugeordnetem Label [Eigene Darstellung], [67].
```

2. Nicht identisch verteilt (Non-IID):
    Nicht identisch verteilte Daten sind Daten, welche nicht unbedingt aus derselben Quelle
    stammen oder die Verteilung der einzelnen Daten (z. B. in Bezug auf die einzelnen Klassen)
    stark variiert. Auch dies kann zu unvorhersehbaren Ergebnissen innerhalb eines Modells
    führen. Inwiefern jedoch Non-IID Daten wirklich einen Einfluss auf das vorliegende Modell
    besitzen, hängt sehr stark von der Art der Daten, der Datenmenge, der Qualität und dem
    Modell ab [11].

Das Transformieren des MNIST-Datensatzes in einen Non-IID Datensatz, um ein realistisches und
praktisches Datenszenario zu simulieren ist recht einfach umzusetzen.

Wie im folgenden Code genauer zu sehen, wurden die Daten vorab in zufällige Gruppen (1 bis 10
Gruppen) unterteilt. Diese Gruppen werden im Anschluss zufällig in ihrem Umfang beschnitten, das
bedeutet, dass eine Gruppe z. B. jeweils 7200 Samples umfasst und die darauffolgende Gruppe
wiederum nur 3000 Samples. Durch diese ungleichmäßige Verteilung der Daten kann man künstlich
ein realistisches Szenario kreieren, welches den Daten der späteren Clients in einer realen Umgebung
wesentlich näher kommt.

```
Abbildung 34 : In der nachfolgenden Abbildung wird ein IID-Datensatz mit einem Non-IID-
Datensatz verglichen. Es zeigt sich somit, dass eine unterschiedliche Verteilung der Daten beider
Datensätze vorliegt. Die unausgewogene Datenverteilung des rechts abgebildeten Datensatzes
kann zu Performance-Problemen innerhalb des Trainings des Clients führen [11].
```

def create_non_iid_data(x, y):
# Random number of groups in the dataset, between 1 and 10
num_partitions = random.randint( 1 , 10 )

partitions = [[] for _ in range(num_partitions)]
labels = [[] for _ in range(num_partitions)]
# Classes of mnist from 0 to 9
classes = np.unique(y)
random.shuffle(classes)

class_distribution = np.array_split(classes, num_partitions)

for i in range(num_partitions):
indices = np.where(np.isin(y, class_distribution[i]))[ 0 ]
x_partition, _, y_partition, _ = train_test_split(x[indices], y[indices], test_size=0.5)
partitions[i] = x_partition
labels[i] = y_partition
return partitions, labels

#### 11.6 Hashing-Algorithmus..............................................................................................................

Hashing ist ein Prozess, bei dem eine Eingabedatenmenge (z. B. eine Datei oder ein Nachrichtentext)
durch eine mathematische Funktion in eine feste Größe von Ausgabedaten, den sogenannten Hash-
Wert oder Hash, umgewandelt wird [68].

Der Hashing-Algorithmus kann für die notwendige Datenintegrität sorgen, da schon eine einzige
Änderung in der Eingabe zu einem abweichenden Hash-Wert als Output führt und so überprüft
werden kann, ob die Daten auf ihrem Weg innerhalb der Kommunikation verändert worden sind.
Hashing unterstützt auch digitale Signaturen und Zertifikate, indem es die Authentizität von
Kommunikationsdaten gewährleistet.

11.6.1 Hashing im Proof-of-Concept

Eines der obersten Ziele des PoC, wie innerhalb der nicht-funktionalen Anforderungen beschrieben, ist
vor allem die Integrität der Daten. Dies bedeutet im näheren Sinne, dass die Daten innerhalb der
Kommunikation zwischen den einzelnen Akteuren im System auf ihrem Weg nicht verändert oder
manipuliert werden dürfen.

Hierfür dient ebenfalls die Blockchain als zusätzliche Instanz, innerhalb der die einzelnen Daten Hashes
hinterlegt sind und so immer von einer Mehrheit im System überprüft werden kann, ob diese Daten
auch so vom Akteur ursprünglich gesendet wurden. Darüber hinaus ist es wesentlich effizienter nicht
die Daten an sich in der Blockchain zu hinterlegen, welche meistens einen großen Speicherplatz
benötigen, sondern lediglich deren Hashwert, welcher sich in Bezug auf seine Länge beim SHA- 256
Hashing-Algorithmus auf lediglich 256 Bits beschränkt.

Innerhalb des Codes und Programms wird hierfür das Packet Hashlib [69] in Python verwendet.
Folgender Code zeigt das Hashing des DL-Modells mittels des SHA-256 Algorithmus durch den
Aggregate-Server als Beispiel.

def hash_model(self, global_model):

hashed_global_model = hashlib.sha3_256(str(global_model).encode('utf-8'))
return hashed_global_model


#### 11.7 Hash-based Message Authentication Code

Der Hash-based Message Authentication Code (HMAC) ist eine Methode zur Berechnung eines
Nachrichtenauthentifizierungscodes unter Verwendung einer kryptografischen Hash-Funktion (vgl.
Hashing-Algorithmus) und eines geheimen Schlüssels [70].

Basierend auf dem Standard RFC 4226 wird HMAC für die Implementierung von HOTP (HMAC-based
One-Time Password) verwendet, einem Algorithmus zur Erzeugung von Einmalpasswörtern.

Der HMAC-Prozess besteht aus zwei Hauptphasen: Zunächst wird die Nachricht mit einem internen
Schlüssel verknüpft und mit einer Hash-Funktion gehasht. Das Ergebnis wird dann mit einem zweiten
Schlüssel verknüpft und erneut gehasht. Die Verwendung eines geheimen Schlüssels in beiden Phasen
gewährleistet die Integrität und Authentizität der Nachricht, da nur Parteien mit Kenntnis des
geheimen Schlüssels gültige HMAC-Werte erzeugen können.

Der HMAC wird u. a. für die Verschlüsselung des Servermodells (vgl. Server Model Encoding
(Verschlüsselung des ML/DL-Modells)) verwendet. Später, wenn der PoC einen optimierten Zustand
erreicht hat, wird der HMAC auch als ein fester Bestandteil bei der Registrierung und Authentifizierung
der einzelnen Akteure verwendet.

#### 11.8 Public-Private-Key Verfahren

In der Cybersecurity wird das Public-Private-Key Verfahren zur sicheren Kommunikation und
Datenverschlüsselung eingesetzt [71]. Es basiert auf einem asymmetrischen kryptografischen System,
welches zwei unterschiedliche, aber mathematisch miteinander verbundene Schlüssel verwendet:
einen öffentlichen Schlüssel (Public Key) und einen privaten Schlüssel (Private Key).

Der Public Key ist öffentlich zugänglich und einsehbar. Dabei wird dieser verwendet, um Daten zu
verschlüsseln oder aber digitale Signaturen bzw. Zertifikate (vgl. Digitale Zertifikate) zu überprüfen.
Der Private Key ist indes nicht öffentlich und bleibt geheim. Mit diesem werden die vom Public Key
verschlüsselten Daten i.d.R. entschlüsselt oder aber digitale Signaturen erstellt.

Nachrichten, die mit dem öffentlichen Schlüssel verschlüsselt wurden, können dementsprechend nur
mit dem privaten Schlüssel entschlüsselt werden. Das heißt, wenn eine Nachricht mit dem
öffentlichen Schlüssel verschlüsselt und mit dem privaten Schlüssel wieder entschlüsselt wurde, kann
davon ausgegangen werden, dass diese Nachricht an den richtigen Empfänger gesendet wurde.

11.8.1 Public-Private-Key Verfahren im Proof-of-Concept
Beim Aufbau einer Kommunikation zwischen den Akteuren werden die einzelnen Akteure zu Beginn
aufgefordert, sich untereinander durch ihre Public-Keys zu authentifizieren. Zusätzlich werden diese
Public-Keys auch verwendet, um anschließend Daten in der Blockchain mit diesen Public-Keys zu
verknüpfen und die Daten so den verantwortlichen Akteuren zuzuordnen. Anschließend dient das
Public-Private-Key Verfahren auch als Grundlage, um eine Verschlüsselung durch AES (vgl. Advanced
Encryption Standard) zwischen den Akteuren aufzubauen. In der praktischen Umsetzung wird hierfür
mittels Python die RSA-Verschlüsselung mit einer Bitlänge von 4096 Bits durch die Library Crypto
implementiert. Folgender Code stellt die Generierung des Private- und Public-Keys der einzelnen
Akteure dar [72].

#private and public keys
random = Random.new().read
RSAkey = RSA.generate( 4096 , random)
self.public = RSAkey.publickey().exportKey()
self.private = RSAkey.exportKey()


#### 11.9 Digitale Zertifikate

Innerhalb der Kommunikation zwischen zwei Parteien bzw. Akteuren müssen sich beide jeweils darauf
verlassen können, dass der jeweilige Public-Key (vgl. Public-Private-Key Verfahren) auch der
entsprechenden Partei gehört, welche diesen übermittelt hat.

Hierfür können digitale Zertifikate eingesetzt werden, wobei eine externe Certificate Authority (CA) die
Zugehörigkeit des Public-Keys zum jeweiligen Akteur bestätigen kann. Hierfür wurde das X.509v3-
Zertifikat verwendet, um innerhalb des PoC die Anwendung derartiger digitaler Zertifikate zu
simulieren [73]. Die Zertifikate des Gateway-Servers, Aggregate-Servers und Clients wurden mithilfe
der Cryptography Library [74] in Python implementiert. Die Zertifikate werden aus Testgründen jedoch

#### selbst von den jeweiligen Akteuren signiert. Dies soll in Zukunft durch eine CA durchgeführt werden.

#### 11.10 Advanced Encryption Standard

AES (Advanced Encryption Standard) ist ein symmetrischer Verschlüsselungsalgorithmus, der in der
Cybersecurity weit verbreitet ist, um Daten zu schützen [75]. Das National Institute of Standards and
Technology (NIST) legte den AES als Verschlüsselungsstandard fest und dieser wurde als RFC-Standard
3565 definiert.

AES verwendet eine Blockverschlüsselung und unterstützt Schlüsselgrößen von 128, 192 und 256 Bit,
was ihn sicher gegen Brute-Force-Angriffe macht. Der Algorithmus verschlüsselt Daten in Blöcken in
Form von Bits (bei einer Schlüsselgröße von 128 umfasst jeder Block 128 Bit) und führt eine Reihe von
Transformationen durch, einschließlich Substitution, Permutation und Mixen, um den Inhalt der Daten
zu verschleiern. AES ist dabei effizient und schnell in seiner Anwendung.

11.10.1 AES-Verschlüsselung im Proof-of-Concept
Da eine durchgehende asymmetrische Verschlüsselung wie RSA (vgl. Public-Private-Key Verfahren) zu
ineffizient für die Kommunikation zwischen z. B. Client und Aggregate-Server ist, wird die
Verschlüsselung nach Austausch der Public-Keys und der Überprüfung der digitalen Zertifikate auf eine
Verschlüsselung durch AES umgestellt. Das bedeutet, dass zu keinem Zeitpunkt nach Austausch der
Schlüssel die Daten unverschlüsselt über das System übermittelt werden. Dennoch kann zwar nicht
der Inhalt der Daten, aber die Aktion, welche durchgeführt wurde, immer noch im Nachgang
nachvollzogen werden.

Im Folgenden Code [76] ist dargestellt, wie mittels AES und dem Python Paket Crypto eine
Verschlüsselung durch AES aufgebaut wird und im Nachgang eine Nachricht verschlüsselt und
entschlüsselt wird.


def set_aes_encryption(self, received_aes_data):

splitServerSessionKey = received_aes_data.split(self.delimiter_bytes)
fSendEnc = splitServerSessionKey[ 0 ]
serverPublic = splitServerSessionKey[ 1 ]

#encode data with private key
private_key = RSA.import_key(self.private)
cipher = PKCS1_OAEP.new(private_key)
fSend = cipher.decrypt(fSendEnc)

#eightbyte is the shared secret
splittedDecrypt = fSend.split(self.delimiter_bytes)
eightByte = splittedDecrypt[ 0 ]
hashOfEight = splittedDecrypt[ 1 ].decode("utf-8")

sess = hashlib.sha3_256(eightByte)
session = sess.hexdigest()

server_public_key = hashlib.sha3_256(serverPublic)
server_public_hash = server_public_key.hexdigest()

return hashOfEight, session, eightByte

def aes_server_encoding(self, data):

iv = os.urandom( 16 )
# Create AES cipher object in CFB mode
cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Encrypt the data
encrypted_data = encryptor.update(data) + encryptor.finalize()

# Return IV concatenated with encrypted data
return iv + encrypted_data

def aes_server_decoding(self, data):

iv = data[: 16 ]
# Create AES cipher object in CFB mode
cipher = Cipher(algorithms.AES(self.AESKey), modes.CFB(iv), backend=default_backend())
decryptor = cipher.decryptor()

# Decrypt the data
decrypted_aes_data = decryptor.update(data[ 16 :]) + decryptor.finalize()

return decrypted_aes_data

Der dargestellte Python-Code besteht aus den folgenden drei Funktionen:

Die erste Funktion „set_aes_encryption“ nimmt verschlüsselte AES-Daten entgegen und verarbeitet
sie. Zunächst wird der empfangene, verschlüsselte Server-Sitzungsschlüssel in zwei Teile geteilt. Der
erste Teil wird dann mit einem privaten RSA-Schlüssel entschlüsselt, um den ursprünglichen AES-
Schlüssel zu erhalten. Dieser entschlüsselte Schlüssel wird weiter in zwei Teile geteilt, um ein acht Byte
langes Secret und dessen Hash zu extrahieren. Diese acht Byte werden gehasht, um einen
Sitzungsschlüssel zu erzeugen. Ebenso wird der zweite Teil, der öffentliche Schlüssel des Servers,
gehasht, um einen öffentlichen Hash zu erzeugen. Schließlich gibt die Funktion den Hash des
Geheimnisses, den Sitzungsschlüssel und die acht Byte zurück.

Die zweite Funktion „aes_server_encoding“ verschlüsselt Daten mithilfe von AES im CFB-Modus.
Zuerst wird ein Initialisierungsvektor (IV) erzeugt. Dann wird ein AES-Cipher-Objekt im CFB-Modus
erstellt und mit diesem der Verschlüsselungsvorgang durchgeführt. Die Funktion gibt die Kombination
aus dem Initialisierungsvektor und den verschlüsselten Daten zurück.


Die dritte und letzte Funktion „aes_server_decoding“ entschlüsselt zuvor verschlüsselte AES-Daten.
Der Initialisierungsvektor wird aus den ersten 16 Bytes der Daten extrahiert. Ein AES-Cipher-Objekt im
CFB-Modus wird erstellt, um die restlichen Daten zu entschlüsseln. Die Funktion gibt die
entschlüsselten Daten zurück.

#### 11.11 Server Model Encoding (Verschlüsselung des ML/DL-Modells)

Das Server Model Encoding ist ein aus einer eigenen geistigen Schöpfung erstelltes Verfahren, welches
gewährleisten soll, dass das verwendete ML/DL-Modell lediglich für zugelassene Akteure einsehbar ist.
In diesem Fall sind dies die registrierten Clients sowie der Aggregate-Server. Das Server Model
Encoding folgt dabei einem bestimmten Ablauf, welcher wie folgt beschrieben werden kann:

1. Der Vorgang beginnt beim Aggregate-
    Server, in welchem das globale Modell
    initiiert wird.
2. Das Modell wird in einem Dictionary
    gespeichert.
3. Dieses Dictionary wird im Anschluss mit
    einem SHA-256 Hashing Algorithmus
    gehasht.
4. Das Dictionary wird in Bytes konvertiert.
5. Das Byte-Dictionary wird zunächst gehasht
    und anschließend mit einem Schlüssel
    wieder verschlüsselt. Der genannte
    Schlüssel wird als "Server Model Encode
    Key" bezeichnet. In der Praxis erfolgt die
    Verschlüsselung unter Zuhilfenahme einer
    Fernet-Key-Verschlüsselung, welche in
    Python implementiert ist. Die in Python
    implementierte Fernet-Key-
    Verschlüsselung basiert auf einer
    Kombination von Advanced Encryption
    Standard (AES) im CBC-Modus mit einem
    128 - Bit-Schlüssel, einem HMAC mit
    SHA256 zur Nachrichtenauthentifizierung
    und einem Initialisierungsvektor (IV) zur
    Sicherstellung der Einzigartigkeit jeder
    Verschlüsselung.
6. In einem späteren Verlauf des Programms übermittelt der Aggregate-Server dem Client den
    Server Model Decode Key, sodass der Client das ML/DL-Modell entschlüsseln und für sein
    lokales Training verwenden kann. Ein Zugriff Dritter auf das Modell ist ohne den Server Model
    Decode Key nicht möglich. Dies gilt auch für den Gateway-Server. In einer späteren


```
Entwicklungsphase soll jeder einzelne Client einen individuellen Server Model Decode Key
erhalten. Derzeit verfügt jeder Client noch über denselben Schlüssel.
```
7. Der Hash des Bytes-Dictionary und das nun verschlüsselte Bytes-Dictionary werden dann in
    ein weiteres Dictionary übertragen.
8. Dieses Dictionary wird ebenfalls in ein Bytes-Format
    konvertiert.
9. Im Anschluss wird das Dictionary nochmals durch
    eine Fernet-Key-Verschlüsselung verschlüsselt. Dies
    dient für die Übertragung an den Gateway-Server.
10. Der Schlüssel, welcher das zweite Dictionary
    verschlüsselte, wird nun mit dem Public-Key des
    Gateway-Servers verschlüsselt.
11. Abschließend erfolgt die Übertragung des
    verschlüsselten Dictionary sowie des Schlüssels für
    das zweite Dictionary an den Gateway-Server,
    woraufhin der Hash des globalen Modells durch den
    Aggregate-Server in der Blockchain gespeichert wird.
    Die Funktionalität des Gateway-Servers ist auf die
    Entschlüsselung der ersten Verschlüsselung des
    Byte-Dictionary beschränkt.


Anhand des dargestellten Codes wird das Server Model Encoding im PoC durchgeführt.

def set_up_model(self):

#init the model
base_global_model = get_model()
self.base_global_model = base_global_model

server_model_data = {
"model_architecture": base_global_model.to_json(),
"model_weights": encode_layer(base_global_model.get_weights()),
}

self.hashed_server_model_data = self.hash_model(server_model_data).hexdigest()

server_model_data_json = json.dumps(server_model_data)
self.global_model = pickle.dumps(server_model_data_json)

#model gets hashed
hashed_global_model = self.hash_model(self.global_model)
self.hashed_global_model = hashed_global_model.hexdigest()

#model gets encrypted by ServerModelEncodeKey set up keys to encrypt and decrypt model and hash
self.server_model_decode_key, self.enc_global_model =
self.encrypt_global_model(self.global_model)

#encrypted Model and Hash of unencrypted Model
enc_model_data_dict = {'EncryptedModel': f'{self.enc_global_model}',
'ModelHash': f'{self.hashed_global_model}'}

enc_model_data_bytes = encode_dict(enc_model_data_dict)
#encrypted model and hash get encrypted by random key Enc(EncModel + Hash)
decrypt_dict_key, encrypted_model_hash_dict =
self.encrypt_final_global_model_hash_dict(enc_model_data_bytes)

#this random key gets encrypted by PK from gateway server
pk_enc_encrypt_key = self.encrypt_decrypt_dict_key(decrypt_dict_key)

#encrypted model and hash get send to gateway
pk_enc_encrypt_key = self.aes_server_encoding(pk_enc_encrypt_key)
self.server_socket.send(pk_enc_encrypt_key)

gateway_got_enc_encryption_key = self.server_socket.recv( 1024 )
gateway_got_enc_encryption_key = self.aes_server_decoding(gateway_got_enc_encryption_key)

if gateway_got_enc_encryption_key == self.get_command_value("command6"):
encrypted_model_hash_dict = self.aes_server_encoding(encrypted_model_hash_dict)
self.server_socket.sendall(encrypted_model_hash_dict)
print("Sending enc model dict to gateway...")

#encrypt globale model with server model encode key
def encrypt_global_model(self, global_model):

server_model_decode_key = Fernet.generate_key()
cipher = Fernet(server_model_decode_key)
encrypted_global_model = cipher.encrypt(global_model)

return server_model_decode_key, encrypted_global_model

#encrypt the model and it ́s hash with a random generated key
def encrypt_final_global_model_hash_dict(self, enc_model_data):

encrypt_dict_key = Fernet.generate_key()
cipher = Fernet(encrypt_dict_key)
encrypted_json_model_data = cipher.encrypt(enc_model_data)

return encrypt_dict_key, encrypted_json_model_data


#### 11.12 Client Validierung

Eine wesentliche Funktion des PoC besteht in der Sicherstellung der Kontrolle über die am System
teilnehmenden Akteure. Nach erfolgter Registrierung des Clients durch den Gateway-Server sowie der
entsprechenden Dokumentation der Daten in der Blockchain initiiert der Client eine Anfrage an den
Aggregate-Server. Im Vorfeld erfolgt eine Prüfung des Clients in der Blockchain durch den Aggregate-
Server, um die Registrierung des Clients zu verifizieren. Nach dem Aufbau einer sicheren
Kommunikation durch RSA, dem digitalen Zertifikat und AES erfolgt seitens des Aggregate-Servers die
Bildung einer sogenannten Encapsulate Class. Diese Klasse bildet den Abschluss des
Kommunikationsprozesses (siehe Abb. 36). Diese Klasse beinhaltet den Hash der Trainingsdaten des
Clients, welcher zuvor bei der Registrierung in der Blockchain hinterlegt wurde. Des Weiteren erfolgt
seitens des Aggregate-Servers die Hinterlegung des Hashes des globalen ML/DL-Modells in derselben
Klasse. Eine nachträgliche Modifikation dieser Klassenattribute ist nicht möglich.

In der Folge übermittelt der Aggregate-Server das globale ML/DL-Modell an den Client. Im Anschluss
überprüft der Client das ML/DL-Modell durch Hashing mit dem Hash, welcher für das ML/DL-Modell in
der Blockchain hinterlegt wurde. Eine Übereinstimmung der Hashes kann als Indiz dafür gewertet
werden, dass das Modell auf dem Kommunikationsweg nicht modifiziert wurde.

Im Anschluss übermittelt der Aggregate-Server die Encapsulate Class an den Client. Im nächsten
Schritt übergibt der Client der Encapsulate Class das globale ML/DL-Modell sowie die Trainingsdaten,
welche als Hash in der Blockchain hinterlegt sind. Im Anschluss werden die Daten innerhalb der Klasse
gehasht und mit den zuvor eingegebenen Hashes abgeglichen. Die Übereinstimmung der Hashes
belegt, dass der Client die anfänglich angegebenen Daten als Trainingsdaten verwendet und das
korrekte Modell verwendet wird. Auf diese Weise lässt sich eine gezielte Manipulation zunächst
eingrenzen.

Innerhalb der Encapsulate Class wurden seitens des Aggregate-Servers zudem diverse Parameter
hinsichtlich der Größe der Trainingsdaten sowie der Modellparameter-Einstellungen (Batch Size,
Epochenanzahl etc.) hinterlegt. In einem nächsten Schritt werden durch den Client, basierend auf den
zuvor festgelegten Parametern, Trainingsdaten aus den Trainingsdaten des Clients zufällig gezogen,
wobei die gleiche Anzahl an Trainingsdaten wie beim Aggregate-Server resultiert. Dadurch wird
gewährleistet, dass beide Parteien über eine exakt gleiche Menge an Trainingsdaten sowie das gleiche
Modell verfügen, was eine Vergleichbarkeit zwischen den beiden Akteuren ermöglicht. Innerhalb des
gesamten Vorgangs ist es dem Client nicht möglich, Einfluss auf den Ablauf und die Parameter
auszuüben.

Das Modell beginnt auf Client-Seite mit dem Training der Client-Trainingsdaten, während auf der Seite
des Aggregate-Servers das Modell ebenfalls das Training mit dessen Trainingsdaten initiiert. Nach
erfolgreichem Abschluss des Trainings kann auf beiden Seiten die Modellgenauigkeit (Model Accuracy)
sowie die Trefferquote (Class Recall) abgelesen werden. Zudem werden die einzelnen Accuracy-
Resultate jeder Klasse angezeigt.

Die Modellresultate innerhalb der Klasse werden auf der Client-Seite mit dem Public-Key des
Aggregate-Servers verschlüsselt, sodass keine Einsicht und kein Zugriff durch den Client auf das
Resultat möglich ist. In der Folge wird das Resultat an den Aggregate-Server übermittelt, der es mit
dem Private-Key entschlüsselt.

In der Folge wird das Trainingsergebnis des Aggregate-Servers mit dem Ergebnis der Clients aus
vorherigen Testdurchläufen im Durchschnitt als allgemeines Ergebnis herangezogen. Sofern das
Resultat des aktuell zu testenden Clients eine signifikante Abweichung vom Durchschnittswert auf der
Aggregate-Server-Seite aufweist, wird dies als eine Anomalie bewertet, was einen Ausschluss des
Clients von der Teilnahme am System zur Folge hat.

Derzeit werden Abweichungen von über 3 % 𝐺𝑀𝐴 zwischen dem Ergebnis des Aggregate-Servers und
des Clients als kritischer Wert erachtet, was einen präventiven Ausschluss des Clients vom Training zur


Folge hat. Es sei darauf hingewiesen, dass es sich bei diesem Wert lediglich um einen Näherungswert
handelt. Der finale, gültige GMA-Wert wird im weiteren Verlauf der praktischen Evaluierungen
schrittweise manifestiert.

Neben der Validierung der jeweiligen Modell-Performance werden darüber hinaus auch die in die
Klasse übermittelten Daten des Clients mit den Beispieldaten des Aggregate-Servers verglichen. Dies
geschieht wiederum auch auf der Clientseite, da die Daten des Clients nicht das lokale Endgerät
verlassen dürfen. Die Daten des Aggregate-Servers sind jedoch nur Beispieldaten, welche auch über
das lokale Endgerät hinaus übermittelt werden dürfen.

```
Abbildung 37 : Die nachfolgende Abbildung präsentiert einen exemplarischen Ausschnitt der Client-Validierung durch den PoC.
Die linke Seite der Abbildung zeigt einen Client, der als "vergiftet" identifiziert wurde, da eine Vertauschung der Labels für die
Klassen 1 und 9 festgestellt wurde. Im Anschluss wurde der Client anhand seiner Modelldaten getestet und das Testergebnis
an den Aggregate-Server übermittelt. Das Resultat der Modell-Performance der Klassen 1 und 9 des Clients ist im roten
Rahmen dargestellt, während das Resultat des Aggregate-Servers im grünen Rahmen ersichtlich ist. Die signifikante
Diskrepanz beider Werte lässt den Schluss zu, dass es sich um eine Label-Flipping-Attacke handelt. [Quelle: Eigene
Darstellung].
```
```
Abbildung 35 : Der konkrete Vorgang, inwiefern der Client vor seiner Teilnahme am Training
vom Aggregate-Server validiert wird [Quelle: Eigene Darstellung].
```

#### 11.13 Defensive Maßnahmen gegen eine Label Flipping Attack

```
Code https://colab.research.google.com/drive/1Kp5NfUh-h1IgY_-65kaIae8AYf-mQGBA?usp=sharing
```
```
Die zuvor aufgezeigte Vielfalt an Angriffsmöglichkeiten auf ein FL-System (vgl. Abschnitt Cyberattacken
auf Federated Learning) verdeutlicht die Relevanz von Schutzmaßnahmen für derartige Systeme. In
der Regel ist unbekannt, welche Art des Angriffs ein Angreifer auf das System wählt. Um jedoch eine
Vergleichbarkeit herstellen zu können, wird auf den PoC der gleiche Angriff durchgeführt, wie er schon
zuvor bei der Testdurchführung zur Ermittlung des Basis-Set-Up (vgl. Ermittlung des Basis Set-Up)
angewandt wurde.
Der Angriff umfasst wiederum eine Label Flipping Attack auf den MNIST-Datensatz, wobei das Label 1
mit dem Label 9 ausgetauscht wird. Das Modell bleibt dabei ebenfalls gleich (vgl. Erstellung des Deep
Learning Modells).
```
```
Das Wissen über die Art und Weise des Angriffs hilft dabei, eine passende Verteidigungsstrategie zu
entwickeln. Im Hinblick auf das Einsatzszenario des PoC ist das Aufbauen einer defensiven Maßnahme
gegen Manipulationen eines Bildklassifikationsmodells passend, da der PoC vorrangig für den
Anwendungsbereich entwickelt wird, bei welchem vor allem Bilddateien eingesetzt werden.
```
```
Um dementsprechend eine Label Flipping Attack bei Bilddaten aufzudecken, eignet sich die Principal
Component Analysis (PCA) bzw. Hauptkomponentenanalyse [77]. Die PCA kann dafür verwendet
werden, sehr hochdimensionale Daten auf eine kleinere Dimension herunterzubrechen bzw. zu
reduzieren und dadurch übersichtlicher zu machen (siehe Abb. 38). So können die einzelnen Werte
der jeweiligen Datensätze von Aggregate-Server und Client ebenfalls in ihrer Dimension reduziert und
genauer verglichen werden.
Der am Ende des Abschnitts aufgeführte Code zeigt, wie die Daten des Aggregate-Servers, welche zum
Teil zum Client gesendet wurden und die Daten des Clients mittels der PCA verglichen werden [78].
```
```
Als erster Schritt werden die Daten so angepasst, dass diese in einem flachen Format vorliegen (jede
Zeile des Datensatzes stellt einen Datenpunkt und alle Merkmale dieses Datenpunkts eine einzige Zeile
dar). Dadurch kann im folgenden Schritt die PCA angewandt werden.
```
_Abbildung 36 : Die Reduzierung der Dimensionen der Daten des MNIST-Datensatzes anhand einer PCA ermöglicht eine anschauliche
Darstellung des Unterschieds zwischen dem nicht vergifteten Datensatz (links) und dem vergifteten Datensatz (rechts). Es lässt sich
eindeutig feststellen, dass die Klassen 9 (orange) und 1 (grau) jeweils vertauscht wurden [Quelle: Eigene Darstellung]._


Die Ergebnisse einer PCA können unter Umständen gut als Plott dargestellt werden (siehe Abb. 38). Da
vor allem aber automatisiert vom Aggregate-Server überprüft werden soll, inwiefern die einzelnen
Daten des Clients und des Aggregate-Servers voneinander abweichen, sollen die Abweichungen nicht
visuell, sondern mittels Durchschnittswerte aufgedeckt werden. So werden im nächsten Schritt die
jeweiligen Durchschnittswerte jeder Klasse jeweils von Client und Aggregate-Server berechnet.

Auch wenn die Abweichung der Werte untereinander der Regel entspricht, sind Ausreißer sicher
identifizierbar. Ausreißer sind Werte, die in Relation zu den restlichen Klassenwerten auffällig große
Abweichungen aufzeigen (siehe Abb. 39). Daher werden als nächster Schritt die Klassenmittelwerte
des Aggregate-Servers mit den Klassenmittelwerten des Clients subtrahiert und zusätzlich die zwei
Klassen mit der größten Differenz markiert und zurückgegeben.

Diese Werte werden abgespeichert und in der Folge mit den Trainingsergebnissen von dem Client und
Aggregate-Server ebenfalls abgeglichen. Die genannten Werte werden in einer Datenbank gespeichert
und mit den Trainingsergebnissen, welche in Abschnitt Client Validierung näher erläutert werden,
abgeglichen. Dies erfolgt sowohl auf Client- als auch auf Aggregate-Server-Ebene.

Sofern zwei Klassen innerhalb der Clientdaten in Bezug auf die Datenunterschiede eine deutliche
Abweichung von den übrigen Klassen aufweisen und diese beiden Klassen im Trainingsergebnis
ebenfalls abweichen (vgl. Abb. 40), wird der Client von der weiteren Teilnahme am System
ausgeschlossen.

```
Abbildung 37 : Das PCA-Ergebnis kann auch numerisch anstatt grafisch (vgl. Abb. 38) dargestellt
werden. Zu sehen ist die berechnete Differenz der Daten des zu validierenden Clients und vom
Aggregate-Server. Wie zu sehen ist weicht das Ergebnis von Klasse 1 und 9 (jeweils rot umrahmt)
sehr stark von den anderen Werten ab [Quelle: Eigene Darstellung].
```
```
Abbildung 38 : Aus der Kombination der festgestellten Abweichung der Trainingsergebnisse zwischen Client und Aggregate-
Server, sowie der Differenz der Datensätze, hat der PoC jeweils eine Einschätzung über den Client abgegeben (siehe roter
Rahmen). In diesem Fall wäre der Client präventiv vom FL-System ausgeschlossen worden [Quelle: Eigene Darstellung].
```

In Folge der Code, der das oben beschriebene im System ausführt.

def validate_client_data(self, server_model_data, client_overwritten_X_train,
client_overwritten_y_train):

def set_pca(server_X_train_flat, client_X_train_flat):

pca = PCA(n_components= 2 )
pca.fit(server_X_train_flat)
pca_server = pca.transform(server_X_train_flat)
pca_client = pca.transform(client_X_train_flat)

return pca_server, pca_client

# Class averages based on the PCA-transformed data
def calculate_class_means(pca_data, y_data):

class_means = {}
num_classes = y_data.shape[ 1 ]

for i in range(num_classes):
class_indices = np.where(np.argmax(y_data, axis= 1 ) == i)[ 0 ]

if class_indices.size > 0 :
class_means[i] = np.mean(pca_data[class_indices], axis= 0 )
else:
class_means[i] = np.nan * np.ones(pca_data.shape[ 1 ])

return class_means

def display_diff(means_server, means_client):

mean_differences = {i: np.nan if np.isnan(means_server[i]).any() or
np.isnan(means_client[i]).any() else np.linalg.norm(means_server[i] - means_client[i]) for i in
means_server}

all_data = pd.DataFrame(list(mean_differences.items()), columns=['class', 'difference'])

sorted_differences = sorted([(class_id, diff) for class_id, diff in
mean_differences.items() if not np.isnan(diff)], key=lambda x: x[ 1 ], reverse=True)
top_outliers = sorted_differences[: 2 ]

top_class_outliers = pd.DataFrame(top_outliers, columns=['class', 'difference'])

return all_data, top_class_outliers

#data of the server
server_X_train = server_model_data["X_train"]
server_y_train = server_model_data["y_train"]

#data of the client to compare
client_X_train = client_overwritten_X_train
client_y_train = client_overwritten_y_train

#prepare the data of server and client to reduce the dimensonality
server_X_train_flat = server_X_train.reshape(server_X_train.shape[ 0 ], - 1 )
client_X_train_flat = client_X_train.reshape(client_X_train.shape[ 0 ], - 1 )

#set the pca following sklearn-framework
pca_server, pca_client = set_pca(server_X_train_flat, client_X_train_flat)

means_server = calculate_class_means(pca_server, server_y_train)
means_client = calculate_class_means(pca_client, client_y_train)

#using pandas to find the differences and the two classes which have the biggest difference
all_data, top_class_outliers = display_diff(means_server, means_client)

#at the end it shows the difference between the data of the server and client and the two
classes which have the biggest difference (maybe cause of label flipping)
return all_data, top_class_outliers


#### 11.13.1 Federated Averaging Algorithmus

Die Aufgabe des Aggregate-Servers ist es die Modellgewichte der Clients innerhalb jeder Runde zu
aggregieren, das bedeutet diese zusammenzufügen und dadurch die globalen Modellgewichte zu
erstellen. Dies basiert in dem vorliegenden PoC auf dem FedAvg-Algorithmus [11]. Im Folgenden
befindet sich die mathematische Notation, die anhand des folgenden Codes umgesetzt und erläutert
wird.

1. Bei einer Clientanzahl 𝐾, wobei 𝑘 ein Client ist, somit 𝑘∈𝐾
2. 𝑤𝑟+ 1 ist das aggregierte globale Modell
3. 𝑤𝑟(𝑘) ist das Modelupdate des Clients 𝑘 innerhalb der Runde 𝑟

##### 𝑤𝑟+ 1 =

##### 1

##### 𝐾

##### ∑𝑤𝑟(𝑘)

```
𝐾
```
```
𝑘= 1
```
def aggregate_client_model_weights(self, client_socket):

client_model_weights = self.get_model_weights()

client_model_weights_list = [client_model_weights]

average_client_model_weights = [
np.mean([weights[i] for weights in client_model_weights_list], axis= 0 )
for i in range(len(client_model_weights_list[ 0 ]))
]

Nachdem die Modellgewichte aggregiert wurden, trainiert der Aggregate-Server mit seinem Modell
und den aggregierten Modellgewichten erneut seine Daten und kontrolliert, ob diverse Anomalien
auftreten, ist dies nicht der Fall, so werden die aktualisierten Modellgewichte bzw. deren Hash in der
Blockchain gespeichert und an die aktualisierten Gewichte an die Clients zurückgesendet.

#### 11.13.2 Clipping

Clipping [79] im Federated Learning bezieht sich auf die Begrenzung der Werte der Modellgewichte
von einzelnen Clients, um die Auswirkungen von böswilligen oder fehlerhaften Beiträgen zu
reduzieren. Dies ist besonders wichtig zur Eindämmung von Label Flipping Attacks, bei denen
Angreifer absichtlich falsche Labels in ihre Trainingsdaten einfügen, um das globale Modell zu
manipulieren. Durch das Clipping werden die extremen Werte der Modellgewichte bzw. Gradienten
auf einen festgelegten Maximalwert beschränkt/geclippt, was die Verfälschung der Ergebnisse der
Aggregation minimiert und somit die Robustheit des globalen Modells gegenüber solchen Angriffen
erhöht.


clip(wr(k),τ), wobei τ der Schwellenwert ist, wann das Modellgewicht des Clients k geclippt wird.

Es ergibt sich folgende aktualisierte FedAvg-Formel [79]:

##### 𝑤𝑟+ 1 =

##### 1

##### 𝐾

##### ∑ 𝑐𝑙𝑖𝑝(𝑤𝑟(𝑘),𝜏)

```
𝐾
```
```
𝑘= 1
```
#### 11.13.3 Byzantine-Resilient Secure Aggregation als Alternative zu FedAvg

Byzantine-resilient Secure Aggregation [80] stellt eine vielversprechende Alternative zum FedAvg-
Ansatz dar. Im Gegensatz zu FedAvg, das auf einem einfachen gewichteten Durchschnitt der lokalen
Modelle basiert (vgl. Federated Averaging Algorithmus), integriert der Byzantine-Resilient Secure
Aggregation einen Mechanismus, um die Robustheit gegen bösartige oder fehlerhafte Teilnehmer
weiter zu erhöhen.

Der Krum-Algorithmus ist dabei die praktische Umsetzung der Byzantine-resilient Secure Aggregation
und spielt dementsprechend eine zentrale Rolle. Grundlegend wählt der Algorithmus das Modell aus,
das den kleinsten Durchschnittsabstand zu allen anderen Modellen aufweist, wodurch die
Auswirkungen von ausreisenden oder manipulierten Modellen minimiert werden.

Es soll anhand des Krum-Algorithmus untersucht werden, ob es möglich ist, den PoC auch hinsichtlich
der Aggregation der Modellgewichte weiter in seiner Robustheit zu stärken.

11.13.3.1 Krum-Algorithmus

#using krum defense mechanism as alternative
def krum(self, client_model_weights_list, num_byzantine):

num_clients = len(client_model_weights_list)
scores = []

for i in range(num_clients):
distances = []
for j in range(num_clients):
if i != j:
distances.append(np.linalg.norm(np.concatenate([client_model_weights_li
st[i][k].flatten() - client_model_weights_list[j][k].flatten() for k in
range(len(client_model_weights_list[ 0 ]))])))
distances.sort()

scores.append(sum(distances[:num_clients - num_byzantine - 2 ]))

krum_index = np.argmin(scores)

return client_model_weights_list[krum_index]

Der Krum-Algorithmus [81] im Code berechnet zunächst die Anzahl der Clients und initialisiert eine
Liste für die Scores. Für jeden Client wird der Abstand zu allen anderen Clients berechnet, wobei die
Abstände als normierte Differenz der Modellgewichte dargestellt werden. Diese Abstände werden
sortiert und die kleinsten Abstände abzüglich der Anzahl der byzantinischen Clients und zwei weiterer
Clients werden summiert und als Score für diesen Client gespeichert. Schließlich wird der Client mit
dem niedrigsten Score ausgewählt und seine Modellgewichte werden als die aggregierten
Modellgewichte zurückgegeben.


#### 11.13.4 FedAvg vs. Krum Algorithmus

Der Testlauf wurde der Vergleichbarkeit halber unter dem zuvor beschriebenen Basis Set-Up
durchgeführt.

Es soll für den PoC getestet werden, welcher Aggregations-Algorithmus eine bessere Modell-
Performance erzielt.

_Testdurchgang 20. FedAvg vs. Krum-Algorithmus_

```
Durchgang Aggregation Clipping Clientanzahl Poisoning
Rate
```
```
GMA GA1C GA9C
```
1 Krum Nein 2 50% 0.9463 0.7926 0.7865
2 FedAvg Nein 2 50% 0.8194 0.3419 0.1548
3 Krum Ja 2 50% 0.8148 0.1972 0.1990
4 FedAvg Ja 2 50% 0.8585 0.7335 0.3680
5 Krum Nein 3 33,3% 0.8188 0.1948 0.1981
6 FedAvg Nein 3 33,3% 0.8362 0.2178 0.2678
7 Krum Ja 3 33,3% 0.8158 0.1977 0.1991
8 FedAvg Ja 3 33,3% 0.8047 0.2087 0.1964
9 Krum Nein 5 20% 0.9409 0.7929 0.7816
10 FedAvg Nein 5 20% 0.9906 0.9958 0.9975
11 Krum Ja 5 20% 0.9838 0.9904 0.9890
12 FedAvg Ja 5 20% 0.9868 0.9917 0.9914
Tabelle 9.0

_Ergebnisse Krum-Algorithmus und FedAvg-Algorithmus_

Die Tabelle zeigt die Ergebnisse des Vergleichs zwischen den Aggregationsmethoden FedAvg und Krum
unter verschiedenen Bedingungen einer steigenden Poisoning Rate, wobei jeweils 5 Runden, 5
Epochen und eine Batch Size von 16 verwendet wurden.

Bei einer Poisoning Rate 𝑃𝑅=50% mit Clientanzahl 𝐾= 2 zeigt Krum ohne Clipping eine sehr hohe
Global Model Accuracy (𝐺𝑀𝐴) von 0.9463, während FedAvg ohne Clipping eine deutlich niedrigere
𝐺𝑀𝐴 von 0.8194 erreicht. Wenn Clipping hinzugefügt wird, sinkt die 𝐺𝑀𝐴 bei Krum auf 0.8148,
während sie bei FedAvg auf 0.8585 steigt. Diese Ergebnisse deuten darauf hin, dass Krum ohne
Clipping besser mit einer hohen Poisoning Rate umgehen kann als FedAvg, während FedAvg mit
Clipping besser performt.

Bei einer Poisoning Rate 𝑃𝑅= 33 ,3% mit Clientanzahl 𝐾= 3 Clients zeigen sowohl Krum als auch
FedAvg ohne Clipping ähnliche 𝐺𝑀𝐴-Werte von 0.8188 bzw. 0.8362. Mit Clipping bleiben die 𝐺𝑀𝐴-
Werte von Krum und FedAvg ebenfalls ähnlich, jedoch leicht niedriger als ohne Clipping. Dies deutet
darauf hin, dass bei einer moderaten Poisoning Rate und einer höheren Anzahl von Clients beide
Methoden ähnlich robust sind, wobei Clipping keinen signifikanten Unterschied macht.

Bei einer Poisoning Rate 𝑃𝑅=20% mit 5 Clients erreicht FedAvg ohne Clipping die höchste 𝐺𝑀𝐴 von
0.9906, dicht gefolgt von Krum ohne Clipping mit einer 𝐺𝑀𝐴 von 0.9409. Mit Clipping erreichen beide
Methoden sehr hohe 𝐺𝑀𝐴-Werte über 0.98, wobei FedAvg mit Clipping die höchste 𝐺𝑀𝐴 von 0.9868
erreicht. Diese Ergebnisse zeigen, dass bei einer niedrigeren Poisoning Rate und einer höheren Anzahl
von Clients beide Methoden sehr robust sind, wobei FedAvg leicht überlegen ist, insbesondere mit
Clipping.

Zusammenfassend lässt sich sagen, dass der Krum-Algorithmus ohne Clipping bei hohen Poisoning
Rates 𝑃𝑅≥ 33 ,3% und einer Clientanzahl 𝐾= 2 besser abschneidet, während FedAvg mit Clipping in


den meisten Szenarien, besonders bei moderaten bis niedrigen Poisoning Rates und mehr Clients, die
beste Leistung erbringt.

Clipping verbessert die Leistung von FedAvg signifikant bei hohen Poisoning Rates, während es bei
Krum weniger Einfluss hat. Im finalen Ergebnis zeigt sich, dass FedAvg ohne das Clipping die beste
Leistung im Durchschnitt gezeigt hat und daher für den PoC verwendet wird. Es könnte jedoch später
andere Konstellationen geben, in denen der Krum-Algorithmus bessere Ergebnisse erzielen könnte,
daher wird dieser dennoch noch als Funktion implementiert.

#### 11.14 Erstellung des Deep Learning Modells

Das DL-Modell innerhalb des PoC musste aus strukturellen Gründen vom Framework PyTorch auf das
Framework Tensorflow umgestellt werden. Die Technologie dahinter ist jedoch gleich und er dürfte
die Testergebnisse nicht allzu stark beeinträchtigen.

model = models.Sequential([
layers.Conv2D( 16 , kernel_size=( 5 , 5 ), padding='same', input_shape=( 28 , 28 , 1 )),
layers.BatchNormalization(),
layers.ReLU(),
layers.MaxPooling2D(pool_size=( 2 , 2 )),

layers.Conv2D( 32 , kernel_size=( 5 , 5 ), padding='same'),
layers.BatchNormalization(),
layers.ReLU(),
layers.MaxPooling2D(pool_size=( 2 , 2 )),

layers.Flatten(),
layers.Dense( 10 ) ])

Da das Modell im Paper „Study of Attacks on Federated Learning“ [32] mit PyTorch als Framework
erstellt wurde, aber dieses Framework noch Probleme hinsichtlich der Kompatibilität mit dem PoC
verursacht, musste das Modell und die dazugehörigen Funktionen, welche unter anderem die Daten
für das Modell bereitstellen, neu mit dem Framework Tensorflow erstellt werden. Das Modell wurde
jedoch inhaltlich eins zu eins aus dem Paper „Study of Attacks on Federated Learning“ [32]
übernommen und an das Framework Tensorflow angepasst.

Dies war eine erste große Herausforderung innerhalb der Durchführung der Tests, da man vorerst ein
tiefes Verständnis beider Frameworks haben musste, bevor man mit der Transformation begann.


#### 11.15 PoC-Aufbau und System-Ablauf

1. Gateway-Server wird gestartet
2. Gateway-Server erstellt seinen eigenen Smart Contract (vgl. Smart Contract). Der Smart Contract
registriert den Gateway-Server als Account auf der Blockchain.
3. Gateway-Server wartet nach Smart-Contract-Initiierung auf eine Verbindungsanfrage.
4. Aggregate-Server wird gestartet.
6. Aggregate-Server versucht sich mit Gateway-Server zu verbinden
7. Nach Verbindungsaufbau mit dem Gateway-Server sendet der Aggregate-Server seinen Public-Key
(vgl. Public-Private-Key Verfahren im Proof-of-Concept) und sein digitales signiertes Zertifikat.
8. Der Gateway-Server verifiziert, ob es sich um den tatsächlichen Public-Key vom Aggregate-Server
handelt durch Überprüfung des digitalen Zertifikats (vgl. Digitale Zertifikate).
9. Falls die Validierung erfolgreich war, sendet der Gateway-Server seinen Public-Key und sein digitales
Zertifikat an den Aggregate-Server.
10. Der Aggregate-Server überprüft ebenfalls, ob die Public-Keys des Gateway-Servers korrekt sind
und das Zertifikat Gültigkeit besitzt.
11. Der Gateway-Server beginnt parallel die notwendigen Parameter für eine Verschlüsselung durch
AES (vgl. AES-Verschlüsselung im Proof-of-Concept) zu erstellen. Diese werden dann an den
Aggregate-Server übermittelt.
12. Der Aggregate-Server überprüft die übermittelten AES-Parameter.


13. Daraufhin wird eine Testnachricht mit dem AES vom Aggregate-Server verschlüsselt und an den
Gateway-Server gesendet.
14. Kann diese Testmessage korrekt vom Gateway-Server entschlüsselt werden und auch die
Bestätigungsmessage vom Gateway-Server an den Aggregate-Server, so ist das Set-Up für die
Verschlüsselung durch AES abgeschlossen. Von jetzt an wird die vollständige Kommunikation zwischen
Aggregate – und Gateway-Server mittels des AES verschlüsselt.
15. Der Gateway-Server initiiert den Smart-Contract für den Aggregate-Server und der Aggregate-
Server wird in der Blockchain registriert.
16. Der Gateway-Server sendet den Smart Contract an den Aggregate-Server.
17. Der Gateway-Server erstellt random eine Reconnection-ID und sendet diese auch an den
Aggregate-Server. Diese Reconnection-ID dient dazu, dass, falls die Verbindung von Gateway und
Aggregate-Server getrennt wird, der Aggregate-Server beim Wiederverbinden beweisen kann, dass er
bereits verifiziert wurde und verbunden war.
18. Der Aggregate-Server initialisiert sein globales Modell.
19. Das Modell wird in Form eines Dictionary aufgeteilt und anschließend gehasht.
20. Anschließend wird das globale Modell mit dem Server-Model-Encode-Key verschlüsselt.
21. Im Anschluss wird das verschlüsselte Modell mit dem Basismodell als Hash noch einmal mit einem
Schlüssel verschlüsselt.
22. Der Schlüssel, der das verschlüsselte Modell und den Modell-Hash verschlüsselt hat, wird mit dem
Public-Key des Gateway-Servers verschlüsselt.
23. Dieser wird wiederum mit AES verschlüsselt und an den Gateway-Server gesendet.


24. Dann wird das verschlüsselte Modell an den Gateway-Server gesendet.
25. Die einzelnen Schichten des globalen Modells werden mit den übertragenen Schlüsseln und
Hashes Stück für Stück entschlüsselt und verglichen. Am Ende ist das Modell für den Gateway-Server
jedoch noch nicht einsehbar, da es noch mit dem Server-Model-Encode-Key verschlüsselt ist. Um das
Modell zu entschlüsseln, wird der Server-Model-Decode-Key verwendet. Diesen erhält jedoch nur ein
registrierter Client. Der Gateway-Server kann lediglich die Integrität des übermittelten Modells
überprüfen.
26. Falls das globale Modell entsprechend entschlüsselt werden konnte, erhält der Aggregate-Server
einen Teilzugriff auf die Funktionen des Smart Contract und kann selbst das globale Modell dort
aktualisieren.
27. Der Gateway-Server überprüft, ob der Aggregate-Server seinen Smart Contract erhalten hat und
wechselt wieder in den offenen Modus und wartet auf neue Connection-Requests.
28. Der Aggregate-Server lädt sein globales Modell bzw. dessen Hash in die Blockchain und wechselt
auch in den offenen Modus, bis ein Client die Verbindung mit dem Aggregate-Server aufnimmt.
29. Der Client wird gestartet
30. Der Client erhält die notwendige Verbindungsadresse, um sich dementsprechend mit dem
Gateway-Server zu verbinden.
31. Der Client verbindet sich mit dem Gateway-Server.
32. Der Client sendet seinen Public-Key, sowie sein digitales Zertifikat an den Gateway-Server.
33. Der Gateway-Server verifiziert wie auch beim Aggregate-Server den Public-Key und das digitale
Zertifikat des Clients und sendet wiederum seinen Public-Key und sein digitales Zertifikat an den
Client.
34. Der Client verifiziert den Public-Key des Gateway-Servers ebenfalls. Anschließend wird auch hier
eine AES-Verschlüsselung aufgesetzt. Ab hier wird jede weitere Kommunikation zwischen Client und
Gateway-Server mittels der AES-Encryption verschlüsselt.
35. Der Client wird in der Blockchain registriert.
36. Der Client erhält seinen Smart Contract und eine Freigabe auf verschiedene Funktionen des Smart
Contracts.
37. Der Client erhält ebenfalls, für denselben Zweck wie der Aggregate-Server eine Reconnection-ID.
38. Der Client fragt den Gateway-Server an, welche Aggregate-Server registriert sind, um sich mit
einem von diesen zu verbinden.
39. Der Client überprüft den Aggregate-Server anhand seines Smart Contracts.
40. Nach Auswahl des Aggregate-Servers übersendet der Gateway-Server dessen globales Modell an
den Client.
41. Der Client überprüft das Modell, welches vom Gateway-Server gesendet wurde, indem er einen
Hash des Modells erstellt und mit dem Hash in der Blockchain vergleicht. Sind beide Hashes identisch,
bedeutet dies, dass das Modell nicht in seiner Integrität verletzt wurde.
42. Nachdem der Client bestätigt hat, dass das globale Modell verifiziert wurde, wechselt der
Gateway-Server wieder in den offenen Modus und wartet auf neue Connections.


43. Der Client beendet seine Verbindung mit dem Gateway-Server und versucht eine Verbindung mit
dem Aggregate-Server aufzubauen.
44. Der Aggregate-Server überprüft bei der neuen Verbindung vorerst, ob es sich um einen Client oder
einen Gateway-Server handelt.
45. Wenn es sich um den Client handelt, werden wie zuvor auch schon die Public-Keys ausgetauscht,
wiederum eine AES-Verschlüsselung aufgebaut.
46. Der Aggregate-Server überprüft mit den Public-Keys des Clients, ob dieser in der Blockchain vom
Gateway-Server registriert wurde.
47. Falls dies zutrifft, wird der Client freigegeben und dieser sendet den Hash des mit dem Server-
Model-Encode-Key verschlüsselten Modells an den Aggregate-Server.


48. Nun werden die Trainingsdaten und der Client getestet (vgl. Client Validierung). Der Aggregate-
Server bildet eine verschlüsselte Klasse. Diese Klasse enthält das korrekte Modell und einen Hash der
Clientdaten. Dazu werden Parameter der Größe der Trainingsdaten hinterlegt.
49. Diese Klasse wird an den Client versendet und dieser hat keine Möglichkeit den Inhalt der Klasse zu
verändern.
50. Der Client übergibt sein zuvor erhaltenes Modell und seine Daten an die Klasse. Innerhalb der
Klasse werden das Modell und die Daten gehasht und mit den hinterlegten vom Client an den
Aggregate-Server übermittelten Hashes verglichen. Falls diese Hashes identisch sind, wird mit einem
relativen Verhältnis der Daten aus dem Client-Datensatz das Modell trainiert.
51. Auch die Beispieldaten des Aggregate-Servers und des Clients werden anhand der
Hauptkomponentenanalyse miteinander verglichen und Anomalien festgestellt.
52. Das Ergebnis des lokalen Clientmodells wird innerhalb der Klasse mit dem Public-Key des
Aggregate-Servers verschlüsselt und an diesen übersendet.
53. Parallel dazu hat der Aggregate-Server einen eigenen Testlauf des Modells mit exakt gleicher
Größe an Trainingsdaten und verhältnismäßig gleichen Bedingungen wie der Testdurchlauf des Clients
durchgeführt.
54. Der Aggregate-Server vergleicht nun sein Ergebnis des Testdurchlaufs und die Ergebnisse der
bereits durchlaufenen Clients mit dem neuen Ergebnis des neuen Clients. Bei einer zu großen
Abweichung der Akkuratheit des Modells, wird der Client abgelehnt und der Vorgang wird
abgebrochen. Zudem werden auch die einzelnen Abweichungen innerhalb der Datensätze beider
Akteure miteinander verglichen.
55. Nachdem der Client ggf. akzeptiert wurde, springt der Aggregate-Server wieder in den offenen
Modus. Der Vorgang, die Clients derart zu testen, wird so lange mit jedem Client wiederholt, bis eine
bestimmte vorher festgelegte Anzahl an Clients beim Gateway-Server und Aggregate-Server registriert
wurde.
56. Der Client beginnt nun mit seinem lokalen Training, anhand des globalen Modells und der Client
Trainingsdaten
57. Nachdem Training werden die Modellgewichte gespeichert und gehashed
58. Der Hash der Modellgewichte wird mit dem Client Device Key für die eindeutige Zuordnung der
Gewichte zum Client in die Blockchain hochgeladen.
59. Falls es sich nicht um die letzte Trainingsrunde handelt, versucht der Client, sich wieder mit dem
Gateway-Server zu verbinden.


60. Der Gateway-Server erhält die Anfrage des Clients und überprüft die mit versendete
Reconnection-ID
61. Es wird erneut eine AES-Verschlüsselung zwischen Gateway-Server und Client aufgebaut.
62. Der Client erhält vom Gateway-Server eine neue Reconnection-ID, um sich ggf. auch in der
nächsten Runde wieder verbinden zu können.
63. Der Client sendet an den Gateway-Server seine Verbindungs-Adresse, damit der Gateway-Server
im Anschluss dem Client eine Anfrage senden kann.
64. Der Client sendet seine Modellgewichte zusammen mit seinem DeviceKey an den Gateway-Server.
65. Der Gateway-Server vergleicht die erhaltenen Modellgewichte, welche vom Client gesendet
wurden, mit den Modellgewichten, die zuvor vom Client in die Blockchain hochgeladen wurden.
Wurde die Integrität nicht verletzt, wird das System wie gewohnt fortgesetzt.
66. Das Sammeln der Modellgewichte der Clients wird so lange wiederholt, bis die gewünschte Menge
an Modellgewichten auf Seiten des Gateway-Server erreicht wurde. Clients, welche bereits ihre
Modellgewichte gesendet haben, gehen in den offenen Modus und warten darauf, bis sich der
Gateway-Server wieder mit ihnen verbindet.
67. Wenn genügend Client Modellgewichte gesammelt wurden, lädt der Gateway-Server den Hash
dieser Modellgewichte in die Blockchain hoch.
68. Dann verbindet sich der Gateway-Server mit dem Aggregate-Server. Beide Server verwenden das
bereits initiierte AES-Verschlüsselungsverfahren.
69. Um sicherzustellen, dass auch wirklich Aggregate-Server und Gateway-Server miteinander korrekt
über AES kommunizieren, erstellt der Aggregate-Server eine zufällige Sequenz in Byte Form und den
Hash dieser Sequenz. Die Sequenz, nicht der Hash, wird an den Gateway-Server gesendet. Dieses
erstellt ebenfalls einen Hash der Bytes und sendet den Hash zurück an den Aggregate-Server. Nur ein
Kommunikationspartner, der über die korrekte AES-Verschlüsselung und das korrekte Hashing verfügt,


könnte diesen Vorgang durchführen. Somit wird getestet, ob es sich um den korrekten
Kommunikationspartner handelt. Der Aggregate-Server vergleicht im Anschluss beide Hashes und gibt
ggf. den Gateway-Server für die Kommunikation frei.

70. Der Gateway-Server sendet nun die gesammelten Client Modellgewichte an den Aggregate-Server.
71. Der Aggregate-Server vergleicht wiederum die erhaltenen Client Modellgewichte mit den
Modellgewichten in der Blockchain.
72. Falls eine zufällige Anzahl an Clients, welche pro Runde am Training partizipieren, ausgewählt
wurde, wird nur eine bestimmte und zufällige Anzahl an Client Modellgewichte für die Aggregation
berücksichtigt.
73. Nach Sammlung der Client Modellgewichte, werden die einzelnen Modellgewichte, der
ausgewählten Clients, vom Aggregate-Server mittels dem FedAvg oder Krum-Algorithmus aggregiert.
74. Der Aggregate-Server macht anschließend erneut einen Testdurchlauf mit den aggregierten
Modellgewichten und überprüft diese auf Anomalien z. B. eine plötzliche massive Reduzierung der
Modellperformance.
75. Die aggregierten Modellgewichte werden als Hash in die Blockchain durch den Aggregate-Server
hochgeladen und dann an den wartenden Gateway-Server zurückgesendet.
76. Im Anschluss geht der Aggregate-Server wieder in den offenen Modus und wartet auf eine neue
Verbindungsanfrage durch den Gateway-Server oder einen Client. War es jedoch die letzte
angegebene Trainingsrunde, wird der Aggregate-Server gestoppt.
77. Der Gateway-Server erstellt wiederum einen Hash der erhaltenen globalen Modellgewichte vom
Aggregate-Server und vergleicht diese mit dem Hash in der Blockchain.
78. Auf der Seite des Gateway-Server werden die empfangenen globalen Modellgewichte nun an die
gespeicherten Clients zurückgesendet. Hierfür greift der Gateway-Server auf die zuvor gespeicherten
Clientadressen zurück (siehe Schritt 63 ) und versucht sich mit diesen wieder zu verbinden.
79. Der Client trainiert nun mit den aktualisierten globalen Modellgewichten sein lokales Modell und
lädt seine neuen trainierten Modellgewichte als Hash wieder in die Blockchain.
80. Handelt es sich nicht um die letzte Trainingsrunde, so startet der Durchgang wieder von neuem
(siehe ab Punkt 54), bis der Aggregate-Server das Training stoppt und keine neuen Verbindungen
mehr akzeptiert
81. Das Programm endet mit einer finalen Trainingsrunde der Clients.
82. Die Clients und der Gateway-Server schließen anschließend ihre Verbindungen.


# 12 Evaluation und Ergebnisse des Proof-of-Concept

Um die Testdurchführungen in Abschnitt Durchschnitts-Performance des Basis Set-Up so realistisch
wie möglich nachzubilden, ist es erforderlich, innerhalb des Experiments möglichst ähnliche und
vergleichbare Bedingungen zu schaffen. Dies beginnt mit der Wahl des zu verwendenden Modells
sowie der Beschaffenheit der vorliegenden Daten.

## 12.1 Durchführung der Label Flipping Attack am Datensatz

def flip_labels(y_train, label1, label2):
flipped_y_train = np.copy(y_train)
flipped_y_train[y_train == label1] = label2
flipped_y_train[y_train == label2] = label1
return flipped_y_train

flipped_y_train = flip_labels(y_train, 1 , 9 )

Die Funktion, die den Datensatz für das Modell aufbereitet, beinhaltet auch die Funktion flip_labels,
die für das Flippen (den Austausch) der Labels der jeweiligen Klassen (im Code zu sehen Klasse 1 und
9) verantwortlich ist. Unterhalb die Abbildung 41, welche eine PCA darstellt, wobei auf der linken Seite
der Datensatz ohne das ausgeführte Label Flipping und auf der rechten Seite der Datensatz mit
durchgeführten Label Flipping einzusehen ist. Bei der Ausführung des PoC muss im Code des Clients
nur angegeben werden, welche Funktion aufgerufen wird, dementsprechend verfügt der Client im
Anschluss über einen vergifteten oder normalen MNIST-Datensatz.

```
Abbildung 39 : Für eine bessere Übersichtlichkeit der PCA wurde die Klasse 1 rot und die Klasse 9 blau markiert.
Die Abbildung zeigt auf der linken Seite den MNIST-Datensatz ohne angewandte Label-Flipping-Attacke. Auf der
rechten Seite wurde wiederum eine Label-Flipping-Attacke mittels der Funktion "flip_labels" (siehe oben)
durchgeführt [Quelle: Eigene Darstellung].
```

### 12.2 Ergebnisse und Resultate des Proof-of-Concept

Der Testdurchlauf anhand des PoC wurde mittels des Basis Set-Up (vgl. Finale Erkenntnisse aus den
Testdurchläufen zur Ermittlung des Basis Set-Up) und einer Clientanzahl von 𝐾= 7 durchgeführt.

_Hardware Set-Up_

32GB DDR4-RAM, GeForce GTX 1650, Intel Core i7-9750H @ 2.60GHz

_Testdurchgang 21. PoC-Performance bei Steigerung der Poisoning Rate_

```
Durchgang Poisoning Rate GMA GA1C GA9C
```
##### 1 14,9% 0.9912 0.9942 0.9929

##### 2 28,5% 0.9897 0.9949 0.9923

##### 3 42,8% 0.8983 0.7900 0.5496

##### 4 57,1% 0.8214 0.3475 0.1545

Tabelle 10.0

#### 12.2.1 PoC-Testdurchlauf

_Disclaimer_
Testdurchläufe können einzelnen starken Schwankungen unterliegen. Die Bedingungen, unter denen
der PoC getestet wurde, sind mit gewissen Adjustierungen in die Realität zu übertragen. Unter
normalen Umständen kann nur selten eine defensive und präventive Maßnahme gegen vergiftete
Clients derart umgesetzt werden, wie sie im PoC durchgeführt wurde.

Bei der Erstellung des PoC wurden die defensiven Maßnahmen im Speziellen auf den MNIST-Datensatz
und einer Label Flipping Attack vorgenommen. Daher erzielt das globale Modell trotz einer Vergiftung
immer noch gute Ergebnisse (siehe Tabelle 10.0). Derartige Ergebnisse sind jedoch in einem realen
Szenario schwer zu erreichen. Es soll dennoch anhand des PoC aufgezeigt werden, welche allgemeinen
Möglichkeiten in Hinblick auf defensive Maßnahmen für ein FL-System bestehen können und es soll
weiter darauf aufgebaut werden.

Der PoC wurde anhand von einer 𝐶𝑙𝑖𝑒𝑛𝑡𝑎𝑛𝑧𝑎ℎ𝑙 𝐾 = 7 getestet. Dennoch liefen die einzelnen
Testdurchläufe störungsfrei ab. Im ersten Durchgang wurde eine 𝑃𝑅= 14 ,9% verwendet.

```
Abbildung 40 : Der Aggregate-Server versucht innerhalb der Client-Validierung Anomalien bzw. Differenzen
in Bezug auf den Client- und Aggregate-Server Datensatz mittels PCA aufzudecken. Hier dargestellt ein
Client bei dem die Labels der Klasse 1 und 9 geflippt wurden [Quelle: Eigene Darstellung].
```

Es wurde wiederum das Basis Set-Up verwendet, um eine direkte Vergleichbarkeit mit dem Basistest
(vgl. Durchschnitts-Performance des Basis Set-Up) durchführen zu können. Das globale Modell des
Aggregate-Servers lieferte eine finale 𝐺𝑀𝐴 von 0.9912, welches ein sehr gutes Ergebnis darstellt. Im
Vergleich das Basis Set-Up ohne den Einsatz des PoC, erreichte unter ähnlichen Bedingungen bei
gleicher 𝑃𝑅 im Durchschnitt eine 𝐺𝑀𝐴 von 0.8708 (vgl. Durchschnitts-Performance des Basis Set-Up).

Es hat sich jedoch im Lauf der Arbeit gezeigt, dass ein präventiver Ausschluss eines vergifteten Clients
wesentlich effektiver für die Modellperformance erscheint, als die vergifteten Modellgewichte des
Clients durch eine stabile Parameter-Einstellung, Clipping und FedAvg auszugleichen.

Wie in Abb. 42 in rot markiert zu erkennen, wurden die geflippten Labels des Clients eindeutig
identifiziert. Zudem war der sich anschließende Vergleich der Modellperformance in Abb. 44 ebenfalls
erfolgreich. Der Aggregate-Server hätte unter diesen Umständen den vergifteten Client aussortiert.
Vor allem das Endergebnis innerhalb des Validierungsprozesses beider einzelnen Akteure war
wiederum auffällig. So erreichte der Client eine Model Accuracy (𝐺𝑀𝐴) von 69,3%, wobei der
Aggregate-Server eine Accuracy (𝐺𝑀𝐴) von ca. 97% erreichte (siehe Abb. 45).

```
Abbildung 41 : Zum Vergleich zu Abb. 36 die Differenz bei einer Client-Validierung, in welcher der getestete Client nicht
vergiftet ist. Dementsprechend ist der Differenz-Wert der Klasse 1 und 9 zwischen Client und Aggregate-Server
wesentlich geringer (umso näher bei 0, umso geringer die Differenz zwischen den Daten) [Quelle: Eigene Darstellung].
```
```
Abbildung 42 : Innerhalb der Testdurchläufe mit dem PoC wurde jeweils vor der Teilnahme eines
neuen Clients, dieser anhand der Client-Validierung geprüft. Oben zu sehen, der Unterschied
zwischen der Modell-Performance (in Bezug auf die einzelnen Klassen) des vergifteten Clients (links),
sowie der Modell des Aggregate-Servers (rechts) [Quelle: Eigene Darstellung].
```

Nach der Validierung der einzelnen Clients (der vergiftete Client wurde im Trainingsverlauf gelassen,
um weitere Auswirkungen testen zu können) wurden die Client Modellgewichte mit dem FedAvg-
Algorithmus, ohne Clipping (vgl. FedAvg vs. Krum Algorithmus), aggregiert, da diese
Aggregationsmethode in den zuvor durchgeführten Testläufen die beste Modellperformance
aufzeigte.

In der Folge werden die Modellgewichte an den Client zurückgesendet und dort aktualisiert. In
Abbildung 46 sind jeweils die Modellperformance des vergifteten Clients (in Rot) sowie das Resultat
eines nicht vergifteten Clients nach der Aggregation (in Grün) dargestellt.

Im Verlauf der Testdurchführung wurde die 𝑃𝑅 auf 4 von 7 bzw. 57,1% erhöht. Es konnten jedoch, wie
in Abb. 47 zu sehen, alle vier vergifteten Clients aufgrund ihrer Anomalien identifiziert und aussortiert
werden.

```
Abbildung 43 : Die Modell-Performance des vergifteten Clients und des Aggregate-Servers, wie in Abb. 38 zu
sehen, resultieren in der allgemeinen GMA, wie oben zu sehen und zeigen auch hier eine große Differenz (Die
GMA wurde im Print Statement im Code fehlerhaft als Precision bezeichnet) [Quelle: Eigene Darstellung].
```
```
Abbildung 44 : Auf der linken Seite (mit den grünen Rahmen) ist ein nicht vergifteter Client dargestellt, der mittels seiner
Testdaten validiert wurde. Auf der rechten Seite ist ein vergifteter Client dargestellt (rote Rahmen), der mit den aktualisierten
Modellgewichten seine vergifteten Daten trainiert hat. Zwischen beiden ist auch hier eine große Differenz innerhalb der
Validierung festzustellen [Quelle: Eigene Darstellung].
```

### 12.3 Performance-Vergleich Basis Set-Up und PoC

Im folgenden Abschnitt wird das Basis Set-Up ohne Verwendung des PoC (Tabelle 11.0) direkt mit dem
Basis Set-Up unter Verwendung des PoC verglichen (Tabelle 11.1). Die Parameter-Einstellungen sind
bei einer 𝑃𝑅= 14 ,9% exakt dieselben innerhalb beider Testdurchläufe.

_Testdurchgang 22. Durchschnittsperformance Basis Set-Up bei Poisoning Rate 14,9%_

Tabelle 11.0

Die oberen Werte wurden der Tabelle 5.0 entliehen.

```
Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
```
##### 1 0.9265 0.9266 0.9723 0.9488 0.9303 0.9008

##### 2 0.7709 0.7662 0.8435 0.8546 0.9973 0.5827

##### 3 0.8806 0.8781 0.9936 0.9819 0.9665 0.8107

##### 4 0.8888 0.8888 0.8953 0.7815 0.9726 0.9217

##### 5 0.8873 0.8892 0.9928 0.9441 0.7392 0.8037

```
Durchschnitt 0.8708 0.8697 0.9395 0.9021 0.9211 0.8039
```
```
Abbildung 45 : Im Rahmen eines Testdurchlaufs mit dem PoC wurden vier von insgesamt sieben Clients als
Anomalien identifiziert. Der PoC war in der Lage, die jeweiligen Clients von den nicht vergifteten Clients zu
unterscheiden und die Abweichungen aufzuzeigen (Die GMA wurde im Print Statement im Code fehlerhaft
als Precision bezeichnet) [Quelle: Eigene Darstellung].
```

_Testdurchgang 23. Durchschnittsperformance PoC bei Poisoning Rate 14,9%_

Tabelle 11.1

Global Model Accuracy Ergebnis Basis Set-Up und PoC

```
Durchgang 𝐺𝑀𝐴 GMR GC1A GC9A GC1R GC9R
```
```
1 0.9913 x 0.9954 0.9929 x x
2 0.9897 0.9662 0.9970 0.9956 0.9921 0.9633
3 0.9892 0.9449 0.9960 0.9953 0.9912 0.9558
4 0.9912 0.9797 0.9940 0.9916 0.9951 0.9767
5 0.9922 0.9848 0.9947 0.9882 0.9965 0.9847
Durchschnitt 0.9905 0.9689 0.9954 0.9927 0.9937 0.9701
```
```
Abbildung 46 : Die Y-Achse zeigt jeweils den Global Model Accuracy-Wert in Prozent an. Die X-Achse listet die
einzelnen Durchgänge von 1 bis 5 auf. Die blaue Linie repräsentiert die Modellergebnisse des PoC, wie in Tabelle
11.1 dargestellt, während die gelbe Linie die Modellergebnisse des Basis Set-Up, wie in Tabelle 11.0 aufgeführt,
widerspiegelt. Die rote Linie repräsentiert den Durchschnittswert der jeweiligen GMA-Werte, welcher sich aus der
Summierung der fünf Testdurchgänge ergibt. Die vorliegenden Ergebnisse legen nahe, dass der PoC hinsichtlich der
GMA eine höhere Genauigkeit aufweist als das Basis Set-Up [Quelle: Eigene Darstellung].
```

Global Class 1 Accuracy Ergebnis Basis Set-Up und PoC

Global Class 1 Recall Basis Set-Up und PoC

```
Abbildung 47 : Der Einfachheit halber wurde in folgender Grafik nur die Modellergebnisse der Klasse 1 in
Hinblick auf die Global Class Accuracy beschrieben. Die einzelnen Elemente der Grafik sind identisch zur Abb.
48, wobei auf der Y-Achse der Wert GC1A aufgeführt wurde. Es ist zu sehen, dass der PoC auch in Hinblick auf
die Modelleistung der Global Class 1 Accuracy durchschnittlich ein besseres und stabileres Ergebnis erzielt,
während die Modellleistung des Basis Set-Up über die einzelnen Durchgänge relativ starken Performance-
Schwankungen unterliegt [Quelle: Eigene Darstellung].
```
```
Abbildung 48 : Dabei zeigen sich keine signifikanten Unterschiede in den Werten zwischen PoC und dem Basis-
Set-Up. Aufgrund eines Messfehlers konnte im Durchgang 5 innerhalb des PoC-Testdurchlaufs kein GC1R-Wert
ermittelt werden. Dennoch zeigt sich in den Durchgängen des PoC ein wiederum sehr stabiler Verlauf, wobei die
Modelleistung des Basis-Setups eine stärkere Schwankung aufweist [Quelle: Eigene Darstellung].
```

# 13 Optimierungsmöglichkeiten des Proof-of-Concept

Trotz einer tiefgehenden Einarbeitung in den PoC und dem Federated Learning gibt es noch eine
Vielzahl an notwendigen Verbesserungen und Optimierungsmöglichkeiten des entworfenen Systems.
Dieser Abschnitt soll dazu dienen, andere einzuladen, den PoC zu verbessern und auf dessen
Grundlage weitere Ideen und Ansätze zu entwickeln. Es liegt in der Natur der Sache, dass nicht alle
Schwachstellen des Systems im Laufe der Bearbeitung aufgedeckt werden konnten, wobei durch die
Anwendung des PoC in einem praktischen Umfeld und außerhalb einer experimentellen Umgebung
weiterhin umfassende Herausforderungen bevorstehen. Es folgen die einzelnen Punkte, welche
praktisch in Zukunft ergänzt, untersucht und bearbeitet werden sollten.

_Probleme mit PyTorch-Modellen und anderen Frameworks_

Wie bereits in Abschnitt Einführung und Ziel der Testdurchführungen aufgezeigt, wurde innerhalb des
Papers „Study of Attacks on Federated Learning“ [32] PyTorch als Framework für das Erstellen und
Validieren des Deep-Learning Modells verwendet. Dies führte jedoch in der praktischen Umsetzung
innerhalb des PoC zu einigen Problemen, vor allem da PyTorch andere Datentypen für seine Trainings -
und Testdaten verwendet als Tensorflow. Es wäre zu erwägen, ob eine Funktion zur Auswahl des
jeweiligen Frameworks integriert werden sollte, um den Nutzer: innen der Applikation eine gewisse
Flexibilität zu bieten.

_Versenden großer Modelle_

Die Größe von ML/DL-Modellen kann sich erheblich unterscheiden, was zu Schwierigkeiten bei der
Übermittlung des jeweiligen Modells zwischen den Beteiligten führen kann. Des Weiteren sind diese
Daten verschlüsselt. Es ist erforderlich, die Kommunikation zwischen den Akteuren langfristig zu
beobachten, um festzustellen, ob sie eine notwendige Stabilität beibehält.

_Data-Preprocessing_

Das Vorbereiten der Daten, um diese mittels eines ML/DL-Modells zu trainieren, benötigt in der Regel
einen vorgegebenen Prozessablauf, welcher die Daten normalisiert und aufbereitet. Da diese Daten
innerhalb eines FL-Systems auf einem lokalen Endgerät gespeichert sind, also kein Zugriff auf diese
Daten besteht und sich diese Daten normalerweise von Gerät zu Gerät auch stark unterscheiden, ist
ein allgemeiner Prozess zur Aufbereitung der Daten eine große Herausforderung.

_Defensive Maßnahmen gegen andere Angriffe als Label Flipping_

Innerhalb der vorliegenden Arbeit, näher im PoC, wurden einzig und allein defensive Maßnahmen
gegen eine Label Flipping Attack getroffen. Es gibt, wie in Abschnitt Cyberattacken auf Federated
Learning zu sehen, wesentlich mehr Möglichkeiten ein FL-System zu manipulieren. Dementsprechend
müssen in der Zukunft weiterführende defensive Maßnahmen getroffen werden, um auch
alternativen Angriffsmöglichkeiten entgegenzuwirken.

_PCA bei anderen Datensätzen_

Für das Aufdecken von Differenzen innerhalb der Daten des Clients und Aggregate-Servers wurde die
Hauptkomponentenanalyse (PCA) verwendet. Diese zeigte anhand des MNIST-Datensatzes bei einer
Label Flipping Attack verlässliche Werte an. Dennoch kann das Resultat dieses Testdurchgangs nicht
ohne weiteres auf andere Datensätze und Angriffsmethoden übertragen werden. Dies bedeutet, dass
der PoC als Clientvalidierung weitere und andere Methoden anwenden muss, um Anomalien innerhalb
der Daten aufdecken zu können.


_Clipping bei vielen Modellgewichten_

Bei einer erhöhten Clientanzahl 𝐾 von über sieben Clients zeigte sich ein Programmfehler im Ablauf
des PoC und das Clipping konnte nicht weiter durchgeführt werden. Die Ursache, wieso das Clipping
bei einer Clientanzahl 𝐾 > 6 nicht durchgeführt werden konnte, wurde anhand des Codes noch nicht
aufgedeckt.

_Krum und FedAvg Testdurchführungen_

Das Ausmaß der Vergleichstest zwischen dem Krum -und FedAvg-Algorithmus sollte in Zukunft noch
vergrößert werden und noch mehr verschiedene Parameter überprüft werden.

_Gateway -und Aggregate-Server als ein einziger Akteur oder getrennt_

Die Gateway -und Aggregate-Server sind momentan noch zwei getrennte Akteure, ggf. kann eine
Kombination dieser beiden Akteure noch andere Möglichkeiten der Nutzung in Zukunft bieten.

_Immer nur ein_ Aggregate- _Server pro FL-System_

Der aktuelle Stand des PoC ist, dass es immer nur einen Gateway-Server, sowie Aggregate-Server gibt.
Es sollen jedoch später in dem bestehenden FL-System mehrere Aggregate-Server existieren, die von
den Clients bedient werden können.

_Blacklist für die Verbindungsadressen_

Es gibt bereits erstellte Blacklists von Unternehmen, die angeboten werden und gefährliche
Verbindungsadressen auflisten. Auch sollte der gesperrte Client, welcher z. B. anhand einer
fehlgeschlagenen Client-Validierung aussortiert wurde, ebenfalls auf diese Blacklist gesetzt werden.
Dies ist für die Testdurchführungen jedoch nicht aktiviert worden, da sonst eine wiederholte
Verbindung durch die Clients nicht durchgeführt werden könnte.

_Random Clients Auswahl noch vor dem Training_

Der Aggregate-Server erhält alle Modellgewichte, aller teilnehmenden Clients und wählt anschließend
von diesen Modellgewichten eine bestimmte Anzahl aus. Es ist effizienter präventiv auszuwählen,
welche Clients in der kommenden Runde ihre Modellgewichte aggregieren lassen, sodass nicht alle
Clients pro Runde am Training teilnehmen müssen.

_GUI oder Web-App_

Da innerhalb der nicht-funktionalen Anforderungen die Benutzerfreundlichkeit weniger im Fokus
stand, sollte jedoch im Anschluss der PoC auch in Form einer Web-App durch den Client bedient
werden können. Sofern die Umsetzung einer Web-Applikation die erforderlichen
Sicherheitsmechanismen sowie die geforderte Leistung nicht gewährleisten kann, ist eine
Weiterentwicklung der grafischen Benutzeroberfläche (GUI) vorgesehen.

_Serverdaten in der Encapsulate Class_

Im Rahmen der Clientvalidierung übermittelt der Aggregate-Server exemplarische Daten an den Client,
um eine Gegenüberstellung der Modellperformance beider Akteure zu ermöglichen. Der aktuelle
Prozess ist noch nicht vollständig ausgereift. Es wäre wünschenswert, einen alternativen Ansatz zu
finden, der einen Vergleich der Modellperformances ermöglicht, ohne dass der Aggregate-Server
seine Daten übermitteln muss. Dies würde zu einer höheren Sicherheit und Effizienz führen.


_Kautionssystem_

Zum aktuellen Stand zahlt der Gateway-Server stellvertretend die Kaution für die Clients und den
Aggregate-Server. Dies liegt daran, dass innerhalb eines lokalen Netzwerks unter dem Einsatz von
Ganache, die einzelnen Smart Contracts nicht sonderlich flexibel übertragbar sind und das innerhalb
der Testdurchführungen des PoC nicht mit realen Währungen bezahlt werden sollte. Zudem muss
noch ein Zahlungssystem auf Seiten der Clients und des Aggregate-Servers eingeführt werden, über
das diese z. B. mittels Ether oder einer anderen Währung ihre Kaution einzahlen.

_Logging-System_

Im Allgemeinen werden die wichtigsten Aktionen der Akteure bereits durch die Blockchain erfasst,
jedoch muss langfristig überprüft werden, ob das Erfassen bzw. das Logging der Aktionen ausreicht,
die entsprechenden Verantwortlichkeiten den einzelnen Akteuren bei einem Fehlverhalten auch
zuordnen zu können.

_Schnittstelle für Clients_

Das System soll später auch von Nutzenden verwendet werden, welche keine Expert*innen im Bereich
der KI sind. Dementsprechend müssen die einzelnen Schnittstellen der Clients leicht bedienbar sein,
ohne dass tiefgreifendes Wissen vorausgesetzt wird.

_Modell-Auswahl_

In Zukunft soll flexibel auf der Seite des Aggregate-Server zwischen mehreren Modell-Alternativen
ausgewählt werden können.


# 14 Fazit und Ausblick

In dieser Arbeit wurde ein Proof-of-Concept entwickelt der dabei helfen soll, diversen
Herausforderungen in Bezug auf Cyberattacken auf das Federated Learning entgegenwirken zu
können. Zu diesem Zweck wurden zunächst die einzelnen grundlegenden Thematiken, wie Federated
Learning und Blockchain, vorgestellt sowie die Bedrohungen, welchen die Technologien ausgesetzt
sind, erörtert. Im Anschluss wurde eine praktische Annäherung an die Thematik der Auswirkungen
dieser Bedrohung auf ein FL-System durch die Durchführung verschiedener Tests vorgenommen,
wodurch ein Umgang mit FL-Systemen erlernt wurde.

Den nächsten Teil der Arbeit umfasste hauptsächlich der PoC, welcher vorerst beschrieben und
einzelne Einsatzszenarien aufgezeigt wurden. In der Folge wurde auch dieser PoC anhand von Tests
einer näheren Betrachtung unterzogen und mit einem alternativen FL-System hinsichtlich seiner
Performance verglichen. Im Anschluss wurden die einzelnen Optimierungsmöglichkeiten für den PoC
präsentiert und Weiterentwicklungsmöglichkeiten für die Zukunft diskutiert.

_Finale Erkenntnisse_

Im Lauf der Arbeit sind dabei wesentliche Erkenntnisse entstanden:

1. Prävention als effizienteste Schutzmaßnahme
    Die Evaluierung diverser Maßnahmen zum Schutz des Aggregations-Algorithmus, wie
    beispielsweise das Clipping oder der Krum-Algorithmus, hat gezeigt, dass insbesondere der
    präventive Ausschluss von Clients am FL-System einen stabilen Trainingsverlauf fördert. Dies
    impliziert, dass Vergiftungen durch den Client, soweit in der vorliegenden Arbeit erörtert,
    durch Maßnahmen wie Parameter-Einstellungen etc. nicht vollständig verhindert werden
    konnten. Daher sollte in Zukunft der Fokus auf die Entwicklung eines Systems gelegt werden,
    welches primär auf die Erkennung von Vergiftungen durch einen Präventionsmechanismus
    abzielt.
2. Gezielter Einsatz der Blockchain
    In vielen der vorgestellten Architekturen (vgl. Blockchain Federated Learning Architekturen)
    wurde die Blockchain in großem Umfang innerhalb der Systeme eingesetzt. Dabei waren die
    einzelnen Akteure teilweise auch Teil der Blockchain. Dies führte zu einer hohen Komplexität
    und einem hohen Ressourcenverbrauch. Der vorgestellte PoC konzentrierte sich jedoch auf
    einen gezielten Einsatz von Blockchain-Technologien, um eine Überlastung des Systems zu
    vermeiden. So wurde die Blockchain neben der Erstellung von Smart Contracts nur für ihre
    ursprüngliche Aufgabe, die Verhinderung von nachträglicher Datenmanipulation, eingesetzt.
3. Verbesserte Leistung eines FL-Systems

```
Der Performancevergleich in Abschnitt Performance-Vergleich Basis Set-Up und PoC zeigt eine
durchschnittlich verbesserte Performance des Systems auf Seiten des PoC. Darüber hinaus
konnten in den durchgeführten Tests Manipulationen durch böswillige Clients erkannt und
dargestellt werden.
```
4. Untersuchung von Modellparametern für eine gesteigerte Robustheit gegenüber einer Label
    Flipping Attack
    In Abschnitt Ermittlung des Basis Set-Up wurden die Auswirkungen der Veränderungen der
    Modellparameter bei einer Label Flipping Attack untersucht. Es hat sich dabei gezeigt, dass die
    Parameter-Kombination aus 5 Runden, 5 Epochen, einer Batch Size von 16 und vier Clients pro
    Runde anhand der Testdurchläufe die jeweils größte Robustheit gegenüber einer Label
    Flipping Attack der Klasse 1 und 9 aufgezeigte (vgl. Abschnitt Ermittlung des Basis Set-Up).


```
Dies bedeutet, dass eine Einstellung der Modellparameter durchaus eine defensive
Maßnahme gegen eine Label Flipping Attack darstellen kann. Zudem wurde gezeigt, dass das
Flippen unterschiedlicher Klassen auch unterschiedliche Auswirkungen auf das Modellresultat
haben kann (vgl. Label Flipping Attack bei Klasse 1 und 9 und 3 und 8).
```
Da der Bereich des Federated Learning und der Künstlichen Intelligenz allgemein großen Umbrüchen
unterliegt, ist es fraglich, welche Entwicklungen innerhalb dieser Technologie in nächster Zeit
aufkommen werden. Noch ist Federated Learning ein Ansatz, der nicht sonderlich oft in der Praxis in
Erwägung gezogen wird und zum Einsatz kommt. Dies liegt einerseits an der fehlenden Infrastruktur,
andererseits aber auch an der fehlenden Kenntnis vieler Personen über diese Technologie.

Die vielen beschriebene Herausforderungen stellen unter Umständen jedoch kein Hindernis dar, die
den Einsatz von Federated Learning langfristig verhindern könnten, da jede Technologie, mehr oder
weniger neue Herausforderungen an seine Nutzer*innen stellt und viele dieser Herausforderungen
ebenfalls im Gebiet der allgemeinen Künstlichen Intelligenz zu finden sind.

Es bedarf noch vieler weiterer Untersuchungen in diesem Bereich, bevor derartige Systeme aktiv in
den Alltag eingebunden werden können und für Nutzer*innen frei zugänglich sind. Jedoch wäre ein
Einsatz innerhalb bestimmter Einrichtungen schon heute denkbar, da diese unter Umständen die
passende Umgebung bereitstellen, derartige Systeme zu installieren.


# 15 Literaturverzeichnis

```
[1] J. Hendler, „Avoiding another AI Winter", ResearchGate, [Online]. Verfügbar:
https://www.researchgate.net/publication/3454567_Avoiding_Another_AI_Winter (abgerufen:
14.06.2024).
```
```
[2] P. Došenović et al., „Artificial Intelligence in the Workplace“, cais-research, [Online]. Verfügbar:
https://www.cais-research.de/wp-content/uploads/Factsheet- 3 - Workplace.pdf (abgerufen:
21.07.2024).
```
```
[3] Future of Life Institute, „Artikel 53: Verpflichtungen für Anbieter von KI-Modellen für
allgemeine Zwecke“, EU Artificial Intelligence Act, [Online]. Verfügbar:
https://artificialintelligenceact.eu/de/article/53/ (abgerufen: 27.06.2024).
```
```
[4] M. Muthuppalaniappan und K. Stevenson, „Healthcare cyber-attacks and the COVID- 19
pandemic: an urgent threat to global health“, International Journal for Quality in Health Care,
Bd. 33, Nr. 1, 2021, doi: 10.1093/intqhc/mzaa117.
```
```
[5] D. Tirth, A. Sai Anirudh und S. Satyam, „ChatGPT in medicine: an overview of its applications,
advantages, limitations, future prospects, and ethical considerations“, Frontiers in Artificial
Intelligence, Bd. 6, 2023, doi: 10.3389/frai.2023.1169595.
```
```
[6] Q. Li et al., „A Survey on Federated Learning Systems: Vision, Hype and Reality for Data Privacy
and Protection“, arXiv, [Online]. Verfügbar: https://arXiv.org/pdf/1907.09693 (abgerufen:
01.06.2024).
```
```
[7] T. Li, A. K. Sahu, A. Talwalkar und V. Smith, „Federated Learning: Challenges, Methods, and
Future Directions“, IEEE, [Online]. Verfügbar: https://ieeexplore.ieee.org/document/9084352
(abgerufen: 01.06.2024).
```
```
[8] Z. Zhang et al., „Explainable Artificial Intelligence Applications in Cyber Security: State-of-the-Art
in Research“, ResearchGate, [Online]. Verfügbar:
https://www.researchgate.net/publication/363171324_Explainable_Artificial_Intelligence_Appl
ications_in_Cyber_Security_State-of-the-Art_in_Research (abgerufen: 03.06.2024).
```
```
[9] L. Heiko und N. Baracaldo, „Federated Learning A Comprehensive Overview of Methods“,
Cham, Schweiz: Springer, 2022.
```
```
[10] D. C. Nguyen et al., „Federated Learning Meets Blockchain in Edge Computing: Opportunities
and Challenges“, IEEE Internet of Things Journal, Bd. 8, Nr. 16, 2021, doi:
10.48550/arXiv.2104.01776.
```
```
[11] V. N. Iyer, „A review on different techniques used to combat the non-iid and heterogeneous
nature of data in FL“, arXiv, [Online]. Verfügbar:
https://arXiv.org/html/2401.00809v1#:~:text=Non%2DIID%20data%20implies%20that,same%2
0underlying%20distribution%20breaks%20down (abgerufen: 11.07.2024).
```
```
[12] P. M. Mammen et al., „Federated Learning: Opportunities and Challenges“, arXiv, [Online].
Verfügbar: https://arXiv.org/pdf/2104.01776 (abgerufen: 12.07.2024).
```
```
[13] Weichert et al., „A review of machine learning for the optimization of production“, The
International Journal of Advanced Manufacturing Technology, Nr. 104, S. 1889–1902, 2019, doi:
10.1007/s00170- 019 - 03988 - 5.
```

[14] A. Hamza, S. Mohmmed und A. Mohammad, „Detecting Data Poisoning Attacks in Federated
Learning for Healthcare Applications Using Deep Learning“, Iraqi Journal for Computer Science
and Mathematics, Nr. 4, S. 225-237, 2023, doi: 10.52866/ijcsm.2023.04.04.018.

[15] Europäisches Parlament und Rat der Europäischen Union, „Verordnung (EU) 2016/679 des
Europäischen Parlaments und des Rates“, eur-lex.europa, [Online]. Verfügbar: https://eur-
lex.europa.eu/legal-content/DE/TXT/PDF/?uri=CELEX:32016R0679 (abgerufen: 8 Mai 2024).

[16] S. Qiu, Q. Liu, S. Zhou und C. Wu, „Review of Artificial Intelligence Adversarial Attack and
Defense Technologies“, MDPI, [Online]. Verfügbar: https://www.mdpi.com/2076-3417/9/5/909
(abgerufen: 05.06.2024).

[17] M. A. Ramirez et al., „Poisoning Attacks and Defenses on Artificial Intelligence: A Survey“, arXiv,
[Online]. Verfügbar: https://arXiv.org/abs/2202.10276 (abgerufen: 05.06.2024).

[18] J. Chen et al., „Invisible Poisoning: Highly Stealthy Targeted Poisoning Attack“, in 15th
International Conference, Inscrypt 2019, Nanjing, China, S. 173–198, 2019, doi: 10.1007/978- 3 -
030 - 42921 - 8_10.

[19] H. He, K. Zha und D. Katabi, „Indiscriminate Poisoning Attacks on Unsupervised Contrastive
Learning“, arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2202.11202 (abgerufen:
27.06.2024).

[20] N. M. Jebreel, J. Domingo-Ferrer, D. Sánchez und A. Blanco-Justicia, „Defending against the
Label-flipping Attack in Federated Learning“, arXiv, [Online]. Verfügbar:
https://arXiv.org/abs/2207.01982 (abgerufen: 27.06.2024).

[21] A. Krizhevsky, V. Nair und G. Hinton, „The CIFAR-10 dataset“, cs.toronto.edu, [Online].
Verfügbar: https://www.cs.toronto.edu/~kriz/cifar.html (abgerufen: 05.08.2024).

[22] B. Wang et al., "Neural Cleanse: Identifying and Mitigating Backdoor Attacks in Neural
Networks", IEEE, [Online]. Verfügbar: https://ieeexplore.ieee.org/document/8835365
(abgerufen: 11.05.2024).

[23] X. Han et al., „Physical Backdoor Attacks to Lane Detection Systems in Autonomous Driving“,
arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2203.00858 (abgerufen: 07.06.2024).

[24] H. Hu und J. Pang, „Stealing Machine Learning Models: Attacks and Countermeasures for
Generative Adversarial Networks“, ACM, [Online]. Verfügbar:
https://dl.acm.org/doi/pdf/10.1145/3485832.3485838 (abgerufen: 06.08.2024).

[25] R. T. Mercuri und P. G. Neumann, „Inside risks: Security by obscurity“, Communications of the
ACM, Bd. 46, Nr. 11, S. 160, 2003, doi: 10.1145/948383.948413.

[26] The OWASP Foundation, „Manipulator-in-the-middle attack“, OWASP, [Online]. Verfügbar:
https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack (abgerufen:
11.05.2024).

[27] C. Xie, K. Huang, P.-Y. Chen und B. Li, „DBA: DISTRIBUTED BACKDOOR ATTACKS AGAINST
FEDERATED LEARNING“, OpenReview, [Online]. Verfügbar:
https://openreview.net/pdf?id=rkgyS0VFvr (abgerufen: 05.06.2024).

[28] H. Zhang et al., „Denial-of-Service or Fine-Grained Control: Towards Flexible Model Poisoning
Attacks on Federated Learning“, arXiv, [Online]. Verfügbar: https://arXiv.org/pdf/2304.10783
(abgerufen: 11.07.2024)


[29] Y. Fraboni, R. Vidal und M. Lorenzi, „Free-rider Attacks on Model Aggregation in Federated
Learning“, arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2006.11901 (abgerufen:
05.06.2024).

[30] W. Wie et al., „A Framework for Evaluating Gradient Leakage Attacks in Federated Learning“,
arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2004.10397 (abgerufen: 07.06.2024).

[31] C. Fung, C. J.M. Yoon und I. Beschastnikh, „Mitigating Sybils in Federated Learning Poisoning“,
arXiv, [Online]. Verfügbar: https://arXiv.org/abs/1808.04866 (abgerufen: 07.06.2024).

[32] T. J. Cheng, „Study of Attacks on Federated Learning“, Nanyang Technological University
Singapore, [Online]. Verfügbar: https://dr.ntu.edu.sg/handle/10356/154018 (abgerufen:
05.05.2024).

[33] Keras, „Accuracy Metrics“, Keras, [Online]. Verfügbar:
https://keras.io/api/metrics/accuracy_metrics/ (abgerufen: 05.08.2024).

[34] Keras, „Classification Metrics“, Keras, [Online]. Verfügbar:
https://keras.io/api/metrics/classification_metrics/ (abgerufen: 05.08.2024).

[35] Scikit-learn developers, „Classification Report“, Scikit-learn, [Online]. Verfügbar: https://scikit-
learn.org/stable/modules/generated/sklearn.metrics.classification_report.html (abgerufen:
05.08.2024).

[36] X. Ying, „An Overview of Overfitting and its Solutions“, Journal of Physics: Conference Series, Bd.
1168, Nr. 2, 2019. doi: 10.1088/1742-6596/1168/2/022022

[37] A. K. P. Anil und U. K. Singh, „An Optimal Solutionto the Overfittingand Underfitting Problemof
Healthcare Machine Learning Models“, Journal of Systems Engineering and Information
Technology, Bd. 2, Nr.2, S. 77-84, 2023, doi: 10.29207/joseit.v2i2.5460.

[38] K. Kaur, R. Dhir und K. Kumar, „Transfer Learning approach for analysis of epochs on
Handwritten Digit Classification“, IEEE, [Online]. Verfügbar:
https://ieeexplore.ieee.org/document/9478102 (abgerufen: 07.07.2024).

[39] U. Michelucci, „Applied Deep Learning A Case-Based Approach to Understanding Deep Neural
Networks“, Dübendorf, Schweiz: Apress, 2018.

[40] Scikit-learn developers, „Cross-Validation“, Scikit-learn, [Online]. Verfügbar: https://scikit-
learn.org/stable/modules/cross_validation.html#cross-validation (abgerufen: 05.08.2024).

[41] Keras, „Model Training APIS“, Keras, [Online]. Verfügbar:
https://keras.io/api/models/model_training_apis/ (abgerufen: 04.08.2024).

[42] Keras, „Losses“, Keras, [Online]. Verfügbar: https://keras.io/api/losses/ (abgerufen:
04.08.2024).

[43] H. Kaur et al., „Federated learning: a comprehensive review of recent advances and
applications“, Springer, [Online]. Verfügbar: https://link.springer.com/article/10.1007/s11042-
023 - 17737 - 0 (abgerufen: 15.07.2024).

[44] PyTorch, „Pytorch Tutorials“, PyTorch, [Online]. Verfügbar: https://pytorch.org/tutorials/
(abgerufen: 03.08.2024).

[45] K.Kawaguchi, L. P. Kaelbling und Y. Bengio, „Generalization in Deep Learning“, arXiv, [Online].
Verfügbar: https://arXiv.org/abs/1710.05468 (abgerufen: 01.07.2024).


[46] P. Rathee, "Advanced Applications of Blockchain Technology", Singapur: Springer, 2019.

[47] S. Corwin, „Ethereum“, Ethereum Org., [Online]. Verfügbar:
https://ethereum.org/en/developers/docs/consensus-mechanisms/pos/ (abgerufen:
15.07.2024).

[48] Z. Wang et al., „A Systematic Survey of Blockchained Federated Learning“, arXiv, [Online].
Verfügbar: https://arXiv.org/abs/2110.02182 (abgerufen: 07.07.2024).

[49] Z. Cai et al., „Blockchain-empowered Federated Learning: Benefits, Challenges, and Solutions“,
arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2403.00873 (abgerufen: 07.07.2024).

[50] K. Liu et al., „A survey on blockchain-enabled federated learning and its prospects with digital
twin“, Digital Communications and Networks, Bd. 10, Nr. 2, S. 248-264, 2024, doi:
10.1016/j.dcan.2022.08.001

[51] Flower Labs , „Flower AI“, Flower Labs GMBH, [Online]. Verfügbar: https://flower.ai/
(abgerufen: 17.06.2024).

[52] V. Buterin, „Ethereum White Paper A NEXT GENERATION SMART CONTRACT & DECENTRALIZED
APPLICATION PLATFORM“, Blockchainlab, [Online]. Verfügbar:
https://blockchainlab.com/pdf/Ethereum_white_paper-
a_next_generation_smart_contract_and_decentralized_application_platform-vitalik-
buterin.pdf (abgerufen: 02.07.2024).

[53] L. Besançon et al., „A Blockchain Ontology for DApps Development“, IEEE, [Online]. Verfügbar:
https://ieeexplore.ieee.org/document/9770809 (abgerufen: 01.07.2024).

[54] H. Hassan, R. Hassan und E. Gbashi, „E-voting System Based on Ethereum Blockchain
Technology Using Ganache and Remix Environments“, Engineering and Technology Journal, Bd.
41, Nr. 4, S. 562-577, 2022, doi: 10.30684/etj.2023.135464.1273.

[55] bitcoincore.org, „Bitcoin Core integration/staging tree“, GitHub, [Online]. Verfügbar:
https://github.com/bitcoin/bitcoin/tree/master (abgerufen: 23.07.2024).

[56] Python Software Foundation, „Python“, python.org, [Online]. Verfügbar:
https://www.python.org/ (abgerufen: 27.07.2024).

[57] M. Abadi et al., „TensorFlow: A System for Large-Scale,“ in 12th USENIX Symposium on
Operating Systems Design, OSDI 16, Savannah (Georgia), USA, Nov. 2016.

[58] Python Software Foundation, „socket — Low-level networking interface“, python.org, [Online].
Verfügbar: https://docs.python.org/3/library/socket.html (abgerufen: 17.06.2024).

[59] Y. Liu, L. Zhang, N. Ge und G. Li, „A Systematic Literature Review on Federated Learning: From A
Model Quality Perspective“, arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2012.01973
(abgerufen: 17.06.2024).

[60] H. Balzert, „Lehrbuch der Softwaretechnik“, Heidelberg, Deutschland: Spektrum Akademischer
Verlag, 2011.

[61] M. Soliman, „Universität Potsdam Rechtskunde Online“, Universität Potsdam, [Online].
Verfügbar: https://www.uni-potsdam.de/de/rechtskunde-
online/rechtsgebiete/strafrecht/prozessrecht/ablauf-des-strafverfahrens (abgerufen:
11.07.2024).


[62] Bundesamt für Sicherheit in der Informationstechnik (bsi), „Kriterien für die Bewertung der
Sicherheit von Systemen der Informationstechnik“, Deutsche IT-Sicherheitskriterien
(Grünbuch), [Online]. Verfügbar:
https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Zertifizierung/ITSicherheitskriterien/i
tgruend_pdf.pdf?__blob=publicationFile&v=1 (abgerufen: 07.06.2024).

[63] Python Sofware Foundation, „Python Errors and Exceptions“, python.org, [Online]. Verfügbar:
https://docs.python.org/3/tutorial/errors.html (abgerufen: 17.07.2024).

[64] Red Hat Inc, „RedHat Was sind latenzempfindliche Anwendungen?“, Red Hat Inc, [Online].
Verfügbar: https://www.redhat.com/de/topics/edge-computing/latency-sensitive-applications.
(abgerufen: 17.07.2024).

[65] M. Adnan et al., „Federated learning and diferential privacy for medical image analysis“, Nature,
2022, doi: 10.1038/s41598- 022 - 05539 - 7.

[66] The Solidity Authors, „soliditylang“, The Solidity Authors, [Online]. Verfügbar:
https://docs.soliditylang.org/en/latest/introduction-to-smart-contracts.html (abgerufen:
17.07.2024).

[67] Tensorflow, „Tensorflow MNIST“, Tensorflow, [Online]. Verfügbar:
https://www.tensorflow.org/datasets/catalog/mnist (abgerufen: 17.07.2024).

[68] The Internet Society, „US Secure Hash Algorithms (SHA and HMAC-SHA)“, rfc-editor, [Online].
Verfügbar: https://www.rfc-editor.org/rfc/rfc4634.html (abgerufen: 07.07.2024).

[69] Python Software Foundation, „hashlib — Secure hashes and message digests“, python.org,
[Online]. Verfügbar: https://docs.python.org/3/library/hashlib.html (abgerufen am 7 07 2024).

[70] The Internet Society, „HOTP: An HMAC-Based One-Time Password Algorithm“, rfc-editor,
[Online]. Verfügbar: https://www.rfc-editor.org/rfc/rfc4226.html (abgerufen: 07.07.2024).

[71] B. Kaliski, „Public-Key Cryptography Standards (PKCS)“, rfc-editor, [Online]. Verfügbar:
https://www.rfc-editor.org/rfc/rfc5208.txt (abgerufen: 07.07.2024).

[72] Cryptography, „RSA“, cryptography.io, [Online]. Verfügbar:
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/ (abgerufen: 07.07.2024).

[73] D. Cooper et al., „Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation
List (CRL) Profile“, datatracker, [Online]. Verfügbar:
https://datatracker.ietf.org/doc/html/rfc5280.html (abgerufen: 08.07.2024).

[74] Cryptography, „X.509 Reference“, cryptography.io, [Online]. Verfügbar:
https://cryptography.io/en/latest/x509/reference/ (abgerufen: 08.07.2024).

[75] J. Schaad, „Use of the Advanced Encryption Standard (AES) Encryption Algorithm in
Cryptographic Message Syntax (CMS)“, rfc-editor, [Online]. Verfügbar: https://www.rfc-
editor.org/rfc/rfc3565 (abgerufen: 08.07.2024).

[76] Onboardbase, „AES Encryption & Decryption In Python: Implementation, Modes & Key
Management“, onboardbase, [Online]. Verfügbar: https://onboardbase.com/blog/aes-
encryption-decryption/ (abgerufen: 07.05.2024).

[77] K. Pothuganti, „OVERVIEW ON PRINCIPAL COMPONENT ANALYSIS ALGORITHM IN MACHINE
LEARNING“, international research journal of science and technology, S. 2582-5208, 2020. doi


[78] Scikit-learn developers, „PCA“, Scikit-learn, [Online]. Verfügbar: https://scikit-
learn.org/stable/modules/generated/sklearn.decomposition.PCA.html (abgerufen: 06.05.2024).

[79] X. Zhang et al., „Understanding Clipping for Federated Learning: Convergence and Client-Level
Differential Privacy“, arXiv, [Online]. Verfügbar: https://arXiv.org/abs/2106.13673 (abgerufen:
18.07.2024).

[80] Y. Xia, C. Hofmeister, M. Egger und R. Bitar, „Byzantine-Resilient Secure Aggregation for
Federated Learning Without Privacy Compromises“, arXiv, [Online]. Verfügbar:
https://arXiv.org/abs/2405.08698 (abgerufen: 07.07.2024).

[81] G. Damaskinos, A. Guirguis und S. Rouault, „krum“, GitHub, [Online]. Verfügbar:
https://github.com/LPD-EPFL/AggregaThor/blob/master/aggregators/krum.py (abgerufen am
11.05.2024).


# Eidesstaatliche Erklärung

Hiermit versichere ich, dass ich die vorgelegte Bachelorarbeit selbstständig verfasst und noch
nichtanderweitig zu Prüfungszwecken vorgelegt habe. Alle benutzten Quellen und Hilfsmittel sind
angegeben, wörtliche und sinngemäße Zitate wurden als solche gekennzeichnet.

Würzburg, den 08.08.2024

Mario von Bassen


