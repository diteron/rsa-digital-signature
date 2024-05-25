#pragma once

class CentralWidget : public QWidget {
public:
    CentralWidget(QWidget* parent = nullptr);
    ~CentralWidget();

    void addLayout(QLayout* layout, int stretch = 0);
    void addWidget(QWidget* widget, int stretch = 0, Qt::Alignment alignment = Qt::Alignment());
    void addStretch(int stretch = 0);

private:
    QVBoxLayout* layout_ = nullptr;
};

