import pandas as pd

class LogAnalyzer:
    def __init__(self, df_logs):
        """
        Constructeur qui initialise l'objet LogAnalyzer avec un DataFrame contenant les logs extraits.

        Paramètres :
        df_logs (pd.DataFrame) : Le DataFrame contenant les informations extraites des logs.
        """
        self.df_logs = df_logs

    def analyser_frequence_ips(self, seuil_alerte=100):
        """
        Analyse la fréquence d'apparition des adresses IP dans les logs.
        Détecte les adresses IP suspectes dépassant un seuil d'alerte.

        Paramètres :
        seuil_alerte (int) : Nombre de requêtes au-delà duquel une adresse IP est considérée comme suspecte.
        """
        if not self.df_logs.empty:
            # Compter le nombre d'occurrences de chaque adresse IP
            frequence_ips = self.df_logs['AdresseIP'].value_counts()

            # Filtrer les adresses IP qui dépassent le seuil d'alerte
            ips_suspectes = frequence_ips[frequence_ips > seuil_alerte]

            # Afficher les adresses IP suspectes
            if not ips_suspectes.empty:
                print(f"\nAdresses IP suspectes dépassant le seuil de {seuil_alerte} requêtes :")
                print(ips_suspectes)
            else:
                print(f"Aucune adresse IP n'a dépassé le seuil de {seuil_alerte} requêtes.")
        else:
            print("Le DataFrame est vide. Assurez-vous d'avoir lu et extrait les logs avant d'analyser les IPs.")