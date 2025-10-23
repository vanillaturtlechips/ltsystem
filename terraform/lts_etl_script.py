import sys
from awsglue.transforms import *
from awsglue.utils import getResolvedOptions
from pyspark.context import SparkContext
from awsglue.context import GlueContext
from awsglue.job import Job
# from pyspark.sql.functions import current_timestamp
from awsglue.dynamicframe import DynamicFrame

# @params: [JOB NAME]
args = getResolvedOptions(sys.argv, ['JOB_NAME', 'S3_OUTPUT_BUCKET'])

sc = SparkContext()
glueContext = GlueContext(sc)
spark = glueContext.spark_session
job = Job(glueContext)
job.init(args['JOB_NAME'], args)

# 크롤러가 생성한 데이터 카틸로그에서 데이터 읽어오기
datasource = glueContext.create_dynamic_frame.from_catalog(
    database = "lts_traffic_data_catalog",
    table_name = "lts_traffic_data_lake_20251023012810334400000001"
)

print("--- Original Data Schema ---")
datasource.printSchema()

spark_df = datasource.toDF()

transformed_frame = DynamicFrame.fromDF(spark_df, glueContext, "transformed_frame")

output_bucket_name = args['S3_OUTPUT_BUCKET']
output_path = f"s3://{output_bucket_name}/processed/"

glueContext.write_dynamic_frame.from_options(
    frame = transformed_frame,
    connection_type = "s3",
    connection_options = {"path": output_path, "partitionKeys": ["year", "month", "day"]},
    format = "parquet"
)

# change lf

job.commit()