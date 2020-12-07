# docker build . -t build-s3fs

s3fs_path=$(docker run --rm build-s3fs sh -c "which s3fs")
id=$(docker create build-s3fs)
docker cp $id:$s3fs_path ./builds/s3fs-$(date '+%Y-%m-%d-%H:%M:%S')
docker rm -v $id
