class Logger:
    def __init__(self, date, threshold, type_attack, email, command, if_warn):
        self.date = date
        self.threshold = threshold
        self.type_attack = type_attack
        self.email = email
        self.command = command
        self.if_warn = if_warn

