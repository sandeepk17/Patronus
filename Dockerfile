FROM centos:centos7

#set versions
ENV JAVA_VERSION=1.8.0
ENV MAVEN_VERSION=3.6.3
ENV GRADLE_VERSION=5.4
ENV NODEJS_VERSION=12.14.0
ENV FIND_SEC_BUGS_VERSION=
ENV DEPENDENCY_CHECKER_VERSION=5.2.4


RUN yum -y update && yum clean all
RUN yum -y install unzip

#install Golang
#RUN mkdir -p /go && chmod -R 777 /go && \
#    yum install -y centos-release-scl && \
#    yum -y install git go-toolset-7-golang && yum clean all
#ENV GOPATH=/go \
#    BASH_ENV=/opt/rh/go-toolset-7/enable \
#    ENV=/opt/rh/go-toolset-7/enable \
#    PROMPT_COMMAND=". /opt/rh/go-toolset-7/enable"
#WORKDIR /go


ENV GOLANG_VERSION 1.12.4
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 d7d1f1f88ddfe55840712dc1747f37a790cbcaa448f6c9cf51bbe10aa65442f5
RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
    && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
    && tar -C /usr/local -xzf golang.tar.gz \
    && rm golang.tar.gz
ENV GOPATH /go
ENV GOROOT /usr/local/go
ENV PATH $GOPATH/bin:$GOROOT/bin:$PATH


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
ENV GRADLE_HOME=/usr/local/gradle-${GRADLE_VERSION}
ENV PATH=$PATH:$GRADLE_HOME/bin JAVA_HOME=/usr/lib/jvm/java-${JAVA_VERSION}-openjdk


#install gosec
SHELL ["/bin/bash", "-c"]
RUN yum -y install git 
RUN go get github.com/securego/gosec/cmd/gosec
RUN cp /go/bin/gosec /usr/bin/


#install cloc
RUN npm install -g cloc

ADD . /root/Patronus
WORKDIR /root/Patronus

RUN mkdir tools
WORKDIR /root/Patronus/tools

#install dependency-check
RUN curl https://dl.bintray.com/jeremy-long/owasp/dependency-check-${DEPENDENCY_CHECKER_VERSION}-release.zip -o dependency_check.zip -L
RUN unzip dependency_check.zip
RUN rm -rf dependency_check.zip

#install find-sec-bugs
RUN curl https://github.com/find-sec-bugs/find-sec-bugs/releases/download/version-1.10.1/findsecbugs-cli-1.10.1.zip -o findsecbugs.zip -L
RUN unzip findsecbugs.zip -d findsecbugs
RUN rm -rf findsecbugs.zip
RUN chmod +x findsecbugs/findsecbugs.sh

WORKDIR /root/Patronus
RUN pip3 install -r requirements.txt


# cronjob
RUN yum -y install cronie
RUN (crontab -l 2>/dev/null; echo "10 08 * * * Patronus/main.py >> /tmp/patronus.txt") | crontab -
CMD python3 main.py