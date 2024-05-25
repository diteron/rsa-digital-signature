#include "stdafx.h"
#include "central_widget.h"

CentralWidget::CentralWidget(QWidget* parent) : QWidget(parent)
{
    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(8, 8, 8, 8);
    setLayout(layout_);
}

CentralWidget::~CentralWidget()
{}

void CentralWidget::addLayout(QLayout* layout, int stretch)
{
    layout_->addLayout(layout, stretch);
}


void CentralWidget::addWidget(QWidget* widget, int stretch, Qt::Alignment alignment)
{
    layout_->addWidget(widget, stretch, alignment);
}

void CentralWidget::addStretch(int stretch)
{
    layout_->addStretch(stretch);
}

