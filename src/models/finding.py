class Finding:
    def __init__(self, finding_id, finding_type, description):
        self.id = finding_id
        self.type = finding_type
        self.description = description

    def __repr__(self):
        return f"Finding(id={self.id}, type={self.type}, description={self.description})"