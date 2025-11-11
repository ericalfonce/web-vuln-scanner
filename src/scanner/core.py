class Scanner:
    def __init__(self):
        self.is_scanning = False

    def start_scan(self):
        self.is_scanning = True
        print("Scanning started...")
        return True

    def stop_scan(self):
        self.is_scanning = False
        print("Scanning stopped.")
        return True