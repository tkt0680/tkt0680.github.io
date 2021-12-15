<%@ Page Title="Home Page" Language="C#" MasterPageFile="~/Site.Master" AutoEventWireup="true" CodeBehind="Default.aspx.cs" Inherits="Adlumin._Default" %>

<asp:Content ID="BodyContent" ContentPlaceHolderID="MainContent" runat="server">
    <style>
        td, th
        {
            padding:5px;
            text-align:center;
            border-color:#cccccc;
        }
        .row{
            margin-top:30px;
        }
    </style>
    <div class="row">
        <div style="width:90%;text-align:center;">
        
            <h3>Please enter copy and paste the data log in the box below</h3>
            
            <asp:TextBox ID="txtData" runat="server" TextMode="MultiLine" CssClass="form-control" Columns="350" Rows="10"></asp:TextBox>
            <div style="padding-top:20px;font-size:16px;">
                <asp:Button ID="btnSubmit" runat="server" CssClass="btn btn-primary btn-lg" OnClick="btnSubmit_Click" Text="Submit" />
                <asp:Button ID="btnClear" runat="server" CssClass="btn btn-primary btn-lg" OnClick="btnClear_Click" Text="Clear" />
              
            </div>
        </div>
    </div>
    <div id="errorMsg" runat="server" class="error"></div>
    <div class="row">
        <asp:UpdatePanel ID="updateP" runat="server">
            <ContentTemplate>
                <asp:GridView ID="gvData" runat="server" AutoGenerateColumns="false" GridLines="Both" Width="90%" HeaderStyle-BackColor="#ee2748" HeaderStyle-ForeColor="White" 
                    AlternatingRowStyle-BackColor="#f5f8fa" OnRowDataBound="gvData_RowDataBound">
                    <Columns>
                        <asp:TemplateField HeaderText="Severity">
                            <ItemTemplate>
                                <asp:Label ID ="lblSeverity" runat="server" Text='<%#Eval("severity") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Date">
                            <ItemTemplate>
                                <asp:Label ID="lblDate" runat="server" Text='<%#Eval("logDate", "{0:MM/dd/yyyy}") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Time">
                            <ItemTemplate>
                                <asp:Label ID="lblTime" runat="server" Text='<%#Eval("logDate", "{0:hh:mm:ss tt}") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Source IP Address">
                            <ItemTemplate>
                                <asp:Label ID="lblIP" runat="server" Text='<%# Eval("src") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Threat Type">
                            <ItemTemplate>
                                <asp:Label ID="lblThreat" runat="server" Text='<%# Eval("cn3") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Action Taken">
                            <ItemTemplate>
                                <asp:Label ID="lblAction" runat="server" Text='<%#Eval("act") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Private or Public IP Address">
                            <ItemTemplate>
                                <asp:Label ID="lblPrivate" runat="server" Text='<%#Eval("privateYN") %>'></asp:Label>
                                
                            </ItemTemplate>
                        </asp:TemplateField>
                        <asp:TemplateField HeaderText="Request URL">
                            <ItemTemplate>
                                <asp:Label ID="lblURL" runat="server" Text='<%# Eval("Request").ToString() == "" ? "N/A" : Eval("Request") %>'></asp:Label>
                            </ItemTemplate>
                        </asp:TemplateField>
                        
                    </Columns>
                </asp:GridView>
                </ContentTemplate>
            </asp:UpdatePanel>
    </div>

</asp:Content>
