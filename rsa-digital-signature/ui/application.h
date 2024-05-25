#pragma once

class Application : public QApplication {
public:
    Application(int& argc, char** argv);
    ~Application();

private:
    void setSystemColorScheme();
};
