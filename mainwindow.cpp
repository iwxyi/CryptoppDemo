#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_pushButton_clicked()
{
    QString plain = ui->plainTextEdit->toPlainText();
    QString key = ui->lineEdit->text();
    ui->plainTextEdit->setPlainText(
                CryptoPPUtil::EncryptString(plain, key));
}

void MainWindow::on_pushButton_2_clicked()
{
    QString plain = ui->plainTextEdit->toPlainText();
    QString key = ui->lineEdit->text();
    ui->plainTextEdit->setPlainText(
                CryptoPPUtil::DecryptString(plain, key));
}
