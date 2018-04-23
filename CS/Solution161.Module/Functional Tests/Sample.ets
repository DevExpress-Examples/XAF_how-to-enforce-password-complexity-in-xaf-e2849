;#DropDB Solution161EasyTest

#Application Solution161Win
#Application Solution161Web

*Action Navigation(User)

*ProcessRecord
 Full Name = ''

#IfDef Solution161Web
*Action Edit
#EndIf
 
*FillForm
 Full Name = Test User
 
*Action Cancel

#IfDef Solution161Win
*HandleDialog
 Respond = Yes
#EndIf

*CheckFieldValues
 Full Name = ''
