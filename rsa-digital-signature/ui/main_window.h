#pragma once

#include "central_widget.h"
#include "algorithms/rsa_digital_signature.h"

#include <filesystem>

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private:    
    void createParamsLayout();
    void createResultOutputLayout();
    void addOpenFileButton();
    void addDigitalSignatureButtons();
    void setupStatusBar();

    std::unique_ptr<RSADigitalSignature> digitalSignature_ = nullptr;
    std::filesystem::path filePath_;
    bool isFileSelected_ = false;

    CentralWidget* centralWidget_;

    QFormLayout* paramsLayout_ = nullptr;
    QLineEdit* pInput_ = nullptr;
    QLineEdit* qInput_ = nullptr;
    QLineEdit* eInput_ = nullptr;

    QFormLayout* resultOutputLayout_ = nullptr;
    QLineEdit* dsOutput_ = nullptr;
    QLineEdit* hashDigestOutput_ = nullptr;
    
    QPushButton* openFile_ = nullptr;
    QStatusBar* statusBar_ = nullptr;
    QLabel* statusBarFileName_ = nullptr;

    QPushButton* addDS_ = nullptr;
    QPushButton* checkDS_ = nullptr;

    const int ButtonsMaxWidth_ = 150;

private slots:
    void openFile();
    void addDigitalSignature();
    void checkDigitalSignature();

private:
    void printDigitalSignatureError() const;
};
