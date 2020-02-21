from app import app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate



db_address = app.config.get('DB_ADDRESS')

class engine_connection:

    def __init__(self):
        """
        Default constructor for db connection
        """
        self.engine = db.create_engine(db_address)
        self.engine.echo = False
        self.connection = self.engine.connect()
        self.metadata = db.MetaData()

    def get_deployment(self, uuid):
       """
       Retrieve the deployment details from dahsboard db.
       This method return a RowProxy object.
       """
       deployments_table = db.Table('deployments', self.metadata, autoload=True, autoload_with=self.engine)
       deployment_selection = db.select([deployments_table]).where(deployments_table.columns.uuid==uuid)
       deployment = self.connection.execute(deployment_selection)

       if deployment.rowcount == 1:
         return deployment.fetchone()

    def get_deployment_dictionary(self, uuid):
       """
       Build python dictionary from RowProxy object.
       """

       rowproxy = self.get_deployment(uuid) 

       deployment_dictionary = {}
       # rowproxy.items() returns an array like [(key0, value0), (key1, value1)]
       for column, value in rowproxy.items():
           # build up the dictionary
           deployment_dictionary = {**deployment_dictionary, **{column: value}}

       return deployment_dictionary

    def get_physical_id(self, uuid):
       """
       """
       deployments = db.Table('deployments', self.metadata, autoload=True, autoload_with=self.engine)
       physid = db.select([deployments.columns.physicalId]).where(deployments.columns.uuid==uuid)
       result = self.connection.execute(physid).fetchone()
       print(result['physicalId'])


#TODO class to create db
#class db_creation:

