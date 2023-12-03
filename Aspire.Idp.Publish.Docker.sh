# 停止容器
docker stop idscontainer
# 删除容器
docker rm idscontainer
# 删除镜像
docker rmi cheng/idsimg
# 切换目录
cd /home/Aspire.Idp
# 发布项目
./Aspire.Idp.Publish.Linux.sh
# 进入目录
cd /home/Aspire.Idp/.PublishFiles/
# 编译镜像
docker build -t cheng/idsimg .
# 生成容器
docker run --name=idscontainer -v /etc/localtime:/etc/localtime -it -p 5004:5004 cheng/idsimg
# 启动容器
docker start idscontainer
