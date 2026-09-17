# Smart Pro Managed Support

## Τι είναι

Το Smart Pro Managed Support διατηρεί μια σταθερή, ελεγχόμενη ταυτότητα υποστήριξης για τη συγκεκριμένη εγκατάσταση Home Assistant.

Όταν η τοπική πολιτική και η εξουσιοδότηση του Broker είναι έγκυρες, μπορεί να διατηρεί τη Managed σύνδεση διαθέσιμη και να επανασυνδέεται αυτόματα μετά από restart του πρόσθετου.

Η παρουσία ενός online node **δεν σημαίνει από μόνη της** ότι ένας τεχνικός έχει πρόσβαση σε Web / Terminal / Files / Desktop. Οι δυνατότητες αυτές ελέγχονται ξεχωριστά από τα αντίστοιχα MeshCentral permissions και από τη ροή εξουσιοδότησης του Smart Pro System.

## Υποστηριζόμενες αρχιτεκτονικές

Η 3.19.0 υποστηρίζει **amd64** και **aarch64**.

Το Broker και το add-on δένουν κάθε λήψη MeshAgent με την πραγματική αρχιτεκτονική του Managed node και επαληθεύουν header, SHA-256, byte count και ELF `e_machine` πριν από foreground εκτέλεση.

Η υποστήριξη aarch64 δεν ενεργοποιεί τα ιστορικά first-device QA εργαλεία σε ARM. Εκείνα παραμένουν κλειδωμένα στο αρχικό τους scope.

## Καθημερινή οθόνη

Η αρχική οθόνη δείχνει πρώτα:
- ID εγκατάστασης,
- αν η αλυσίδα εξουσιοδότησης είναι ολοκληρωμένη,
- την κατάσταση της Managed σύνδεσης,
- health / τελευταίο reason,
- αν είναι ενεργή η αυτόματη επανασύνδεση,
- renewals και reconnects.

Η κάρτα **Μόνιμη Managed σύνδεση** είναι η βασική καθημερινή λειτουργική κάρτα.

Τα πιο τεχνικά στοιχεία — stable node, server watch, health report, runtime lease, identity mode και cleanup — παραμένουν διαθέσιμα μέσα από τα **Τεχνικά στοιχεία runtime**.

## Μετά από επανεκκίνηση ή update

Αν η αυτόματη επανασύνδεση είναι ενεργή, είναι φυσιολογικό να εμφανιστεί προσωρινά **«Αναμονή αυτόματης επανασύνδεσης»**.

Το πρόσθετο περιμένει έγκυρη local + server authorization και προσπαθεί να επαναφέρει το ίδιο stable node.

Μην πατάτε επαναλαμβανόμενα ενεργοποίηση/παύση όσο βρίσκεται σε αυτή την κατάσταση. Αν υπάρχει πραγματικό πρόβλημα, ελέγξτε πρώτα το **Αρχείο καταγραφής** του Home Assistant.

Στη verified 3.19.0 διαδρομή έχουν επιβεβαιωθεί:
- ίδια stable identity μετά από restart,
- Broker `allowed/authorized`,
- continuous runtime recovery,
- νέο lease renewal μετά το restart.

## Router Compatibility

Η 3.19.0 προσθέτει production Router Compatibility για ελεγχόμενη πρόσβαση στον router της εγκατάστασης μέσω MeshCentral WebRelay.

Η διαδρομή είναι:

**MeshCentral WebRelay → Managed Agent → `127.0.0.1:18080` → validated local gateway**

Βασικοί κανόνες ασφαλείας:
- το compatibility endpoint ακούει μόνο στο `127.0.0.1`,
- ο target gateway προκύπτει μόνο από το read-only `smart-pro-managed-network-v1` contract,
- γίνονται έλεγχοι private IPv4, freshness/lease και health flags,
- δεν υπάρχει γενικό/open proxy,
- το router target port είναι σταθερά ελεγχόμενο,
- δεν αποθηκεύονται router credentials,
- το login στον router γίνεται από τον browser του εξουσιοδοτημένου τεχνικού.

Έχουν επαληθευτεί:
- anonymous router page load,
- authenticated login,
- διατήρηση session,
- πλοήγηση σε Wi‑Fi και γενικές ρυθμίσεις,
- σωστή επαναφορά μετά από restart.

Σε ορισμένα router interfaces η πλοήγηση μέσω WebRelay μπορεί να είναι πιο αργή από την άμεση LAN πρόσβαση. Στο τρέχον production QA παρατηρήθηκαν καθυστερήσεις περίπου 10–15 δευτερολέπτων σε ορισμένες ενέργειες.

## Home Assistant WebRelay

Η πρόσβαση στο Home Assistant μέσω WebRelay έχει επαληθευτεί μετά από restart της 3.19.0.

Έχουν επιβεβαιωθεί:
- κανονικό page load,
- login,
- πλοήγηση,
- σωστή UTF‑8 / ελληνική απόδοση.

## Terminal / Files / Desktop

Οι δυνατότητες Terminal / Files / Desktop δεν δίνονται αυτόματα από την έκδοση του add-on.

Η πρόσβαση εξαρτάται από τα MeshCentral permissions και τον εξουσιοδοτημένο τεχνικό ρόλο.

Στο verified production QA:
- η Managed συσκευή παρέμεινε online μετά από restart,
- Terminal συνδέθηκε/αποσυνδέθηκε κανονικά,
- Files συνδέθηκε/αποσυνδέθηκε κανονικά.

## Διαγνωστικά εργαλεία

Τα παλαιότερα diagnostics, migration/recovery εργαλεία και first-device checkpoints δεν έχουν διαγραφεί.

Βρίσκονται σε αναδιπλούμενες ενότητες ώστε να είναι διαθέσιμα σε μελλοντικό incident χωρίς να γεμίζουν την καθημερινή οθόνη.

Κάθε εργαλείο αναφέρει:
- τι επίδραση έχει,
- πότε χρησιμοποιείται,
- ποιες είναι οι προϋποθέσεις,
- αν επιτρέπεται επανάληψη,
- πώς ερμηνεύεται PASS/FAIL.

Στη stable 3.19.0 οι ιστορικές mutation/test ενέργειες παραμένουν κλειδωμένες. Η κατάσταση και η τεκμηρίωσή τους διατηρούνται για forensic troubleshooting και ελεγχόμενα maintenance checkpoints.

## Αν κάτι φαίνεται Offline ή FAILED

1. Μην κάνετε re-pair, reseed ή διαγραφή `/data`.
2. Μην επαναλαμβάνετε one-time diagnostic/mutation actions.
3. Ανοίξτε **Αρχείο καταγραφής** και εξαγάγετε το σχετικό Home Assistant log.
4. Ελέγξτε το Broker diagnostic για την ίδια Installation ID όταν χρειάζεται server-side συσχέτιση.
5. Συγκρίνετε την τρέχουσα έκδοση και τα runtime checkpoints με το τελευταίο verified backup/checkpoint.

## Αρχική ενεργοποίηση πελάτη

Η τελική customer-facing ενεργοποίηση δεν αποτελεί μέρος της 3.19.0.

Η παλιά τεχνική pairing φόρμα παραμένει κλειδωμένη ως ιστορική αναφορά.

Η μελλοντική ροή θα σχεδιαστεί γύρω από το Customer Portal και controlled one-time activation, χωρίς να αλλάζει τη σταθερή Managed identity και χωρίς να παρακάμπτει τα permission boundaries.
