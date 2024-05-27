#include "stdafx.h"
#include "ui/application.h"
#include "ui/main_window.h"

int main(int argc, char *argv[])
{
    Application a(argc, argv);
    MainWindow w;
    w.setMinimumSize(880, 500);
    w.show();
    return a.exec();
}
