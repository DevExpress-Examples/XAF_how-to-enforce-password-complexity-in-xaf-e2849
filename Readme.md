# How to enforce password complexity in XAF


<p>This task can be accomplished by validating user-entered passwords in the ChangePasswordOnLogonParameters and ChangePasswordParameters detail views. Here, we create a code rule to check password complexity using a custom function. This rule should be checked in a custom context, attached to the DialogOK action, because ChangePasswordOnLogonParameters is a non-persistent object, and the Save context is not appropriate for it.<br />
Also, we have to explicitly initialize the validation rule set, otherwise validation won't work prior to user login.</p><p>For additional information, refer to the <a href="http://documentation.devexpress.com/#Xaf/CustomDocument3259"><u>Non Persistent Objects Validation</u></a> help topic.</p>

<br/>


