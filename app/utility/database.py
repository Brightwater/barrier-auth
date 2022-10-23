from databases import Database

database = Database("postgresql://postgres:password@localhost/Barrier-Auth", min_size=1, max_size=10)