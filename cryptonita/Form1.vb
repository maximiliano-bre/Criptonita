Public Class Form1

    Private Sub Button1_Click(sender As Object, e As EventArgs) Handles Button1.Click
        TextBox2.Text = Encryption.Encrypt(TextBox1.Text)
    End Sub

    Private Sub Button2_Click(sender As Object, e As EventArgs) Handles Button2.Click
        TextBox1.Text = Encryption.Decrypt(TextBox2.Text)
    End Sub
End Class
