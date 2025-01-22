from config.include import jobs_collection

def add_job(job_data):
    jobs_collection.insert_one(job_data)

def get_jobs():
    return jobs_collection.find()
