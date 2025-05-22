from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = 'scans'
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    scan_type = db.Column(db.String(64), nullable=True)

    services = db.relationship('Service', backref='scan', lazy=True)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True)

    def __repr__(self):
        return f"<Scan {self.id} - {self.target}>"

class Service(db.Model):
    __tablename__ = 'services'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    version = db.Column(db.String(255), nullable=True)
    port = db.Column(db.String(32), nullable=True)
    protocol = db.Column(db.String(32), nullable=True)

    def __repr__(self):
        return f"<Service {self.name} {self.version} on port {self.port}>"

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    cve_id = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(64), nullable=True)

    def __repr__(self):
        return f"<Vulnerability {self.cve_id} - {self.severity}>"

