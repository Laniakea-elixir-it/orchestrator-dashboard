import sqlalchemy as db

deployments_table = db.Table('deployments', self.metadata, autoload=True, autoload_with=self.engine)

def get_deployment(self, uuid):
   """
   Retrieve the deployment details from dahsboard db.
   This method return a RowProxy object.
   """
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
