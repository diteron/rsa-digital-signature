#include "stdafx.h"

#include "application.h"

Application::Application(int& argc, char** argv) : QApplication(argc, argv)
{
    #ifdef Q_OS_WIN
        setSystemColorScheme();
    #endif
}

Application::~Application()
{}

void Application::setSystemColorScheme()
{
    Qt::ColorScheme systemColorScheme = qApp->styleHints()->colorScheme();
    if (systemColorScheme == Qt::ColorScheme::Dark) {
        setStyle(QStyleFactory::create("fusion"));
    }
}