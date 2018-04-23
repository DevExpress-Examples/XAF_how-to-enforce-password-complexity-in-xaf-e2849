Imports Microsoft.VisualBasic
Imports System
Imports System.Collections.Generic

Imports DevExpress.ExpressApp
Imports System.Reflection
Imports DevExpress.Persistent.Validation
Imports DevExpress.ExpressApp.Security
Imports System.Text.RegularExpressions
Imports DevExpress.ExpressApp.Validation


Namespace Solution161.Module
	Public NotInheritable Partial Class Solution161Module
		Inherits ModuleBase
		Public Sub New()
			InitializeComponent()
		End Sub
		Public Overrides Overloads Sub Setup(ByVal moduleManager As ApplicationModulesManager)
			MyBase.Setup(moduleManager)
			Dim registrator As New ValidationRulesRegistrator(moduleManager)
			registrator.RegisterRule(GetType(PasswordStrengthCodeRule), GetType(IRuleBaseProperties))
			AddHandler Application.SetupComplete, AddressOf application_SetupComplete
		End Sub
		'this code is necessary to enable validation in the "Change Password On First Logon" window.
		Private Sub application_SetupComplete(ByVal sender As Object, ByVal e As EventArgs)
			Dim [module] As ValidationModule = CType((CType(sender, XafApplication)).Modules.FindModule(GetType(ValidationModule)), ValidationModule)
			If [module] IsNot Nothing Then
				[module].InitializeRuleSet()
			End If
		End Sub
	End Class

	<CodeRule> _
	Public Class PasswordStrengthCodeRule
		Inherits RuleBase(Of ChangePasswordOnLogonParameters)
		Public Sub New()
			MyBase.New("", "ChangePassword")
			Me.Properties.SkipNullOrEmptyValues = False
		End Sub
		Public Sub New(ByVal properties As IRuleBaseProperties)
			MyBase.New(properties)
		End Sub
		Protected Overrides Overloads Function IsValidInternal(ByVal target As ChangePasswordOnLogonParameters, <System.Runtime.InteropServices.Out()> ByRef errorMessageTemplate As String) As Boolean
			If CalculatePasswordStrength(target.NewPassword) < 3 Then
				errorMessageTemplate = "password strength is insufficient"
				Return False
			End If
			errorMessageTemplate = String.Empty
			Return True
		End Function
		Private Function CalculatePasswordStrength(ByVal pwd As String) As Integer
			Dim weight As Integer = 0

			If pwd.Length > 1 AndAlso pwd.Length < 4 Then
				weight += 1
			Else
				If pwd.Length > 5 Then
					weight += 1
				End If
				Dim rxUpperCase As New Regex("[A-Z]")
				Dim rxLowerCase As New Regex("[a-z]")
				Dim rxNumerals As New Regex("[0-9]")
				Dim match As Match = rxUpperCase.Match(pwd)
				If match.Success Then
					weight += 1
				End If
				match = rxLowerCase.Match(pwd)
				If match.Success Then
					weight += 1
				End If
				match = rxNumerals.Match(pwd)
				If match.Success Then
					weight += 1
				End If
			End If
			If weight = 3 AndAlso pwd.Length < 6 Then
				weight -= 1
			End If
			If weight = 4 AndAlso pwd.Length > 10 Then
				weight += 1
			End If
			Return weight
		End Function
	End Class



End Namespace
