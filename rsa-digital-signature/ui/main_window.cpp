#include "stdafx.h"
#include "main_window.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent),
    filePath_()
{
    centralWidget_ = new CentralWidget(this);
    setCentralWidget(centralWidget_);
    
    createParamsLayout();
    createResultOutputLayout();
    addOpenFileButton();

    centralWidget_->addStretch();

    setupStatusBar();
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
}

void MainWindow::addDigitalSignature()
{

}

void MainWindow::checkDigitalSignature()
{

}