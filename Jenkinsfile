pipeline {
    agent {
        docker { image 'rust:latest' }
    }
    stages {
        stage('Test') {
            steps {
                sh 'cargo test'
            }
        }
    }
}