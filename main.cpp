#include "mainwindow.h"

/*#include "cryptopp/include/md5.h"
#include "cryptopp/include/filters.h"
#include "cryptopp/include/hex.h"*/
#include <QApplication>
#include <QDebug>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    /*std::string text="abc123";
    std::string digest;
    CryptoPP::Weak1::MD5 md5;
    CryptoPP::HashFilter hashfilter(md5);
    hashfilter.Attach(new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest), false));
    hashfilter.Put(reinterpret_cast<const unsigned char*>(text.c_str()), text.length());
    hashfilter.MessageEnd();
    QString tmp= QString::fromStdString(digest);
    qDebug()<<"md5:"<<tmp;*/

    MainWindow w;
    w.show();
    return a.exec();
}
