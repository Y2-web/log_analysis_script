import argparse
from modules.log_reader import LogReader
from modules.log_analyzer import LogAnalyzer

def main():
    # Gestion des arguments en ligne de commande
    parser = argparse.ArgumentParser(description="Script d'analyse de logs")
    parser.add_argument("repertoire", help="Chemin vers le répertoire contenant les fichiers de logs", type=str)
    parser.add_argument("--pattern", help="Pattern pour filtrer les fichiers de logs (par défaut 'secure*')", type=str, default="secure*")
    parser.add_argument("--seuil", help="Seuil d'alerte pour les adresses IP suspectes", type=int, default=100)
    args = parser.parse_args()

    # Créer une instance de LogReader avec le chemin du répertoire
    lecteur = LogReader(args.repertoire)

    # Trouver tous les fichiers de logs correspondant au pattern dans le répertoire
    fichiers_logs = lecteur.trouver_fichiers_logs(pattern=args.pattern)

    # Si des fichiers de logs sont trouvés, les lire un par un et extraire les informations
    if fichiers_logs:
        for fichier_log in fichiers_logs:
            print(f"\nLecture du fichier : {fichier_log}")
            lecteur.lire_et_extraire_logs(fichier_log)  # Lire et extraire les informations du fichier de logs

        # Créer le DataFrame une fois que tous les fichiers ont été lus
        lecteur.creer_dataframe()

        # Créer une instance de LogAnalyzer pour analyser les logs
        analyseur = LogAnalyzer(lecteur.df_logs)

        # Analyser la fréquence des adresses IP
        analyseur.analyser_frequence_ips(seuil_alerte=args.seuil)

        # Afficher le DataFrame contenant les informations extraites
        # lecteur.afficher_dataframe()
    else:
        print(f"Aucun fichier de logs correspondant au pattern '{args.pattern}' n'a été trouvé dans le répertoire.")

if __name__ == "__main__":
    main()