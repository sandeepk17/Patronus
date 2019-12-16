FROM centos:centos7

#set versions
ENV JAVA_VERSION=1.8.0
ENV MAVEN_VERSION=3.6.1
ENV GRADLE_VERSION=5.4
ENV NODEJS_VERSION=6.4.1


RUN yum -y update && yum clean all
RUN yum -y install unzip

#install Golang
RUN mkdir -p /go && chmod -R 777 /go && \
    yum install -y centos-release-scl && \
    yum -y install git go-toolset-7-golang && yum clean all
ENV GOPATH=/go \
    BASH_ENV=/opt/rh/go-toolset-7/enable \
    ENV=/opt/rh/go-toolset-7/enable \
    PROMPT_COMMAND=". /opt/rh/go-toolset-7/enable"
WORKDIR /go



#intall Nodejs
RUN curl -sL https://rpm.nodesource.com/setup_10.x | bash -
RUN yum -y install nodejs

#install Python3
RUN yum -y install python3

#install java
RUN yum install -y java-${JAVA_VERSION}-openjdk-devel


#Install maven
ARG maven_download_url="http://mirror.dkd.de/apache/maven/maven-3/${MAVEN_VERSION}/binaries/apache-maven-${MAVEN_VERSION}-bin.tar.gz"
ENV MAVEN_DOWNLOAD_URL "${maven_download_url}"
RUN curl ${MAVEN_DOWNLOAD_URL} -o /tmp/maven.tgz && \
    su -c "tar -zxvf /tmp/maven.tgz -C /usr/local"  && \
    ln -s /usr/local/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/local/bin/mvn && \
    ln -s /usr/local/apache-maven-${MAVEN_VERSION}/bin/mvn /usr/local/bin/maven && \
    rm /tmp/maven.tgz
ENV JAVA_HOME=/usr/lib/jvm/java-1.8.0

#install Gradle
RUN \
    cd /usr/local && \
    curl -L https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip -o gradle-${GRADLE_VERSION}-bin.zip && \
    unzip gradle-${GRADLE_VERSION}-bin.zip && \
    rm gradle-${GRADLE_VERSION}-bin.zip

# Export some environment variables
ENV GRADLE_HOME=/usr/local/gradle-${GRADLE_VERSION}
ENV PATH=$PATH:$GRADLE_HOME/bin JAVA_HOME=/usr/lib/jvm/java-${JAVA_VERSION}-openjdk


#install gosec
SHELL ["/bin/bash", "-c"]
RUN go get github.com/securego/gosec/cmd/gosec
RUN cp /go/bin/gosec /usr/bin/


ADD . /root/Patronus
WORKDIR /root/Patronus
RUN pip3 install -r requirements.txt


