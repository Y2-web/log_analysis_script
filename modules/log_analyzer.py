import pandas as pd

class LogAnalyzer:
    def __init__(self, df_logs):
        """
        Constructeur qui initialise l'objet LogAnalyzer avec un DataFrame contenant les logs extraits.

        Paramètres :
        df_logs (pd.DataFrame) : Le DataFrame contenant les informations extraites des logs.
        """
        self.df_logs = df_logs

    def analyser_frequence_ips(self, intervalle_temps='1min', seuil_alerte=10):
        """
        Analyse la fréquence d'accès des adresses IP dans un intervalle de temps.
        Détecte les adresses IP suspectes qui accèdent trop souvent dans un court laps de temps.

        Paramètres :
        intervalle_temps (str) : Intervalle de temps pour l'analyse (par exemple, '1min' pour une minute).
        seuil_alerte (int) : Nombre d'accès au-delà duquel une adresse IP est considérée comme suspecte.
        """
        if not self.df_logs.empty:
            # Convertir la colonne 'Date/Heure' en datetime si ce n'est pas déjà fait
            try:
                self.df_logs['DateHeure'] = pd.to_datetime(self.df_logs['DateHeure'], format='%b %d %H:%M:%S')
            except Exception as e:
                print(f"Erreur lors de la conversion des dates : {e}")
                return

            # Grouper par adresse IP et intervalle de temps
            acces_par_ip = self.df_logs.set_index('DateHeure').groupby(
                [pd.Grouper(freq=intervalle_temps), 'AdresseIP']
            ).size()

            # Filtrer les groupes qui dépassent le seuil d'alerte
            acces_suspects = acces_par_ip[acces_par_ip > seuil_alerte]

            # Afficher les résultats
            if not acces_suspects.empty:
                print(f"\nAccès suspects détectés (plus de {seuil_alerte} accès par IP dans {intervalle_temps}) :")
                print(acces_suspects)
            else:
                print(f"Aucun accès suspect détecté dans l'intervalle de {intervalle_temps}.")
        else:
            print("Le DataFrame est vide. Veuillez charger les logs avant l'analyse.")