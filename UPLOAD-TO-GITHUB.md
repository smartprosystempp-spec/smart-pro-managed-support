# Update Smart Pro Managed Support repository

## Κανονικό add-on update

1. Κρατήστε το ίδιο GitHub repository και το ίδιο add-on slug `smart_pro_managed_support`.
2. Αντικαταστήστε μόνο τα αρχεία που παρέχονται από το νέο verified package.
3. Κάντε commit/push.
4. Στο Home Assistant ανοίξτε Add-on Store → Check for updates.
5. Κάντε **update in place**. Μην κάνετε uninstall και μην διαγράφετε `/data`.

## Για το root-documentation cleanup της 3.18.1

Αν ενημερώνετε μόνο τα root docs του repository, αντικαταστήστε μόνο:

- `README.md`
- `ARCHITECTURE.md`
- `SECURITY.md`
- `UPLOAD-TO-GITHUB.md`
- `CHANGELOG.md`
- `.gitignore` / `repository.yaml` μόνο αν περιλαμβάνονται στο πακέτο

Μην ξανανεβάζετε τον εσωτερικό φάκελο `smart-pro-managed-support/` όταν δεν υπάρχει runtime release.

## Generated Python files

Το repository δεν πρέπει να περιέχει `__pycache__/` ή `*.pyc`. Αν έχουν ήδη γίνει commit, διαγράψτε τα από το GitHub repository. Το `.gitignore` αποτρέπει την επανεισαγωγή τους σε μελλοντικά commits.
