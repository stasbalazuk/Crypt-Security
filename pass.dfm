object PS: TPS
  Left = 559
  Top = 368
  BorderIcons = [biSystemMenu]
  BorderStyle = bsSingle
  Caption = #1055#1088#1086#1074#1077#1088#1082#1072' '#1076#1086#1089#1090#1091#1087#1072' ...'
  ClientHeight = 56
  ClientWidth = 267
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  FormStyle = fsStayOnTop
  OldCreateOrder = False
  Position = poScreenCenter
  OnActivate = FormActivate
  OnCreate = FormCreate
  PixelsPerInch = 96
  TextHeight = 13
  object GroupBox1: TGroupBox
    Left = 0
    Top = 0
    Width = 267
    Height = 56
    Align = alClient
    Caption = #1042#1074#1077#1076#1080#1090#1077' '#1087#1072#1088#1086#1083#1100
    TabOrder = 0
    object password: TEdit
      Left = 8
      Top = 16
      Width = 145
      Height = 28
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlue
      Font.Height = -16
      Font.Name = 'MS Sans Serif'
      Font.Style = [fsBold]
      ParentFont = False
      PasswordChar = '*'
      TabOrder = 0
      OnKeyPress = passwordKeyPress
    end
    object btn1: TButton
      Left = 160
      Top = 16
      Width = 99
      Height = 28
      Caption = #1055#1088#1086#1074#1077#1088#1082#1072
      TabOrder = 1
      OnClick = btn1Click
    end
  end
end
