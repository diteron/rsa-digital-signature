#include "stdafx.h"
#include "main_window.h"

#include "algorithms/sha1.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
    digitalSignature_(),
    filePath_()
{
    centralWidget_ = new CentralWidget(this);
    setCentralWidget(centralWidget_);
    
    createParamsLayout();
    createResultOutputLayout();
    addOpenFileButton();
    addDigitalSignatureButtons();

    centralWidget_->addStretch();

    setupStatusBar();

    digitalSignature_ = std::make_unique<RSADigitalSignature>();
}

MainWindow::~MainWindow()
{}

void MainWindow::createParamsLayout()
{
    paramsLayout_ = new QFormLayout(centralWidget_);
    pInput_ = new QLineEdit(centralWidget_);
    qInput_ = new QLineEdit(centralWidget_);
    eInput_ = new QLineEdit(centralWidget_);
    
    QRegularExpression regex("(\\d+)");
    auto* validator = new QRegularExpressionValidator(regex, centralWidget_);
    pInput_->setValidator(validator);
    qInput_->setValidator(validator);
    eInput_->setValidator(validator);
    eInput_->setText(QString("65537"));

    paramsLayout_->addRow("p: ", pInput_);
    paramsLayout_->addRow("q: ", qInput_);
    paramsLayout_->addRow("e: ", eInput_);

    centralWidget_->addLayout(paramsLayout_);
}

void MainWindow::createResultOutputLayout()
{
    resultOutputLayout_ = new QFormLayout(centralWidget_);
    dsOutput_ = new QLineEdit(centralWidget_);
    hashDigestOutput_ = new QLineEdit(centralWidget_);
    dsOutput_->setReadOnly(true);
    hashDigestOutput_->setReadOnly(true);

    resultOutputLayout_->addRow("Digital Signature: ", dsOutput_);
    resultOutputLayout_->addRow("Hash digest: ", hashDigestOutput_);
    
    centralWidget_->addLayout(resultOutputLayout_);
}

void MainWindow::addOpenFileButton()
{
    openFile_ = new QPushButton("Open File", centralWidget_);
    openFile_->setMaximumWidth(ButtonsMaxWidth_);
    connect(openFile_, &QPushButton::clicked, this, &MainWindow::openFile);
    centralWidget_->addWidget(openFile_);
}

void MainWindow::addDigitalSignatureButtons()
{
    addDS_ = new QPushButton("Sign", centralWidget_);
    addDS_->setMaximumWidth(ButtonsMaxWidth_);
    connect(addDS_, &QPushButton::clicked, this, &MainWindow::addDigitalSignature);

    checkDS_ = new QPushButton("Check signature", centralWidget_);
    checkDS_->setMaximumWidth(ButtonsMaxWidth_);
    connect(checkDS_, &QPushButton::clicked, this, &MainWindow::checkDigitalSignature);

    centralWidget_->addWidget(addDS_);
    centralWidget_->addWidget(checkDS_);
}

void MainWindow::setupStatusBar()
{
    statusBar_ = new QStatusBar(this);
    setStatusBar(statusBar_);
    statusBarFileName_ = new QLabel("File is not selected", statusBar_);
    statusBar_->insertPermanentWidget(0, statusBarFileName_, 1);     // stretch > 0 moves single widget in the status bar to the left side
}

void MainWindow::openFile()
{
    QString fileName = QFileDialog::getOpenFileName(centralWidget_);
    statusBarFileName_->setText(fileName);

    QByteArray byteArr = fileName.toLocal8Bit();
    filePath_ = std::filesystem::path(byteArr.constData());   
    isFileSelected_ = true;
}

void MainWindow::addDigitalSignature()
{
    if (!isFileSelected_) {
        QApplication::beep();
        QMessageBox::warning(nullptr, QApplication::applicationName(),
                             "File not selected");
        return;
    }

    bool isSuccessSetup = digitalSignature_->setupRsaParams(BigInt(pInput_->text().toStdString()),
                                                            BigInt(qInput_->text().toStdString()),
                                                            BigInt(eInput_->text().toStdString()));

    if (!isSuccessSetup || !digitalSignature_->signFile(filePath_)) {
        printDigitalSignatureError();
        return;
    }

    hashDigestOutput_->setText(QString(digitalSignature_->getDigestStr().c_str()));
    dsOutput_->setText(QString(digitalSignature_->getDigitalSignatureStr().c_str()));

    QApplication::beep();
    QMessageBox::information(nullptr, QApplication::applicationName(),
                             "The file was successfully signed.");
}

void MainWindow::checkDigitalSignature()
{

}

void MainWindow::printDigitalSignatureError() const
{
    QString errorText;

    RSADigitalSignature::Error errorCode = digitalSignature_->getLastError();
    switch (errorCode) {
        case RSADigitalSignature::Error::ParamsNotSetup:
            errorText = "RSA parameters is not setup.";
            break;
        case RSADigitalSignature::Error::NotPrime_p:
            errorText = "p is not prime.";
            break;
        case RSADigitalSignature::Error::NotPrime_q:
            errorText = "q is not prime.";
            break;
        case RSADigitalSignature::Error::TooLowModulus:
            errorText = "Too low modulus, enter bigger p and q.";
            break;
        case RSADigitalSignature::Error::Incorrect_e:
            errorText = "Incorrect e.";
            break;
        case RSADigitalSignature::Error::NotCoPrime_e:
            errorText = "e is not coprime to phi(n)";
            break;
        case RSADigitalSignature::Error::FileNotFound:
            errorText = "File not found";
            break;
        default:
            break;
    }

    QApplication::beep();
    QMessageBox::warning(nullptr, QApplication::applicationName(),
                         errorText);
}
