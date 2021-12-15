using System;
using System.Collections.Generic;
using System.Linq;
using System.Data;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Text.RegularExpressions;
using System.Net;
using _123.Utility;

namespace Adlumin
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            
        }
        protected void btnSubmit_Click(object sender, EventArgs e)
        {
            string logData = "";

            logData = StringUtil.FixHTMLString(txtData.Text);

            List<string> batches = new List<string>();
            batches = SplitChunkData(logData);
            

            DataTable parsedData = keyValue(batches);

            DataTable displayDT = new DataTable();

            var distinctList = (from r in parsedData.AsEnumerable() select r["batchID"]).Distinct().ToList();

            var distinctColumns = (from c in parsedData.AsEnumerable() select c["keys"]).Distinct().ToList();

            foreach(string col in distinctColumns)
            {
                string newColName = col.ToString();
                displayDT.Columns.Add(newColName);
            }
            
            displayDT.Columns.Add("privateYN", typeof(string));
            displayDT.Columns.Add("logDate", typeof(DateTime));
            displayDT.Columns.Add("batchID", typeof(int));

            for (int y = 0; y <= distinctList.Count() -1; y++)
            {
                DataRow[] pRow = parsedData.Select("batchID = " + distinctList[y]);

                for (int x = 2; x <= parsedData.Columns.Count - 1; x++)
                {
                    DataRow nRow = displayDT.NewRow();
                    

                    for (int cCount = 0; cCount < pRow.Count() - 1; cCount++)
                    {
                        string colValue = pRow[cCount][x].ToString();
                        nRow[cCount] = colValue;
                    }
                    displayDT.Rows.Add(nRow);
                }

                DateTime timeStampt = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

                DataRow row = displayDT.Rows[y];

                    row["batchID"] = distinctList[y];

                    string ip = row["src"].ToString().Trim();
                    bool isPrivate = checkPrivateIP(ip);
                    string privateYN = isPrivate ? "Y" : "N";
                    row["privateYN"] = privateYN;

                    long date = long.Parse(row["rt"].ToString());
                    timeStampt = timeStampt.AddMilliseconds(date).ToLocalTime();
                    row["logDate"] = timeStampt;
                    displayDT.AcceptChanges();
            }
            gvData.DataSource = displayDT;
            gvData.DataBind();
        }

        protected void gvData_RowDataBound(object sender, GridViewRowEventArgs e)
        {
            if (e.Row.RowType == DataControlRowType.DataRow)
            {
                string threatDes = "";
                

                Label lblPrivate = (Label)e.Row.FindControl("lblPrivate");
                Label lblThreat = (Label)e.Row.FindControl("lblThreat");
                Label lblSeverity = (Label)e.Row.FindControl("lblSeverity");

                switch (lblThreat.Text.Trim())
                {
                    case "0":
                        threatDes = "Malicious content";
                        break;
                    case "1":
                        threatDes = "Malicious behavior";
                        break;
                    case "2":
                        threatDes = "Suspicious behavior";
                           break;
                    case "3":
                        threatDes = "Exploit";
                        break;
                    case "4":
                        threatDes = "Grayware";
                        break;                          
                }
                lblThreat.Text = threatDes;
                string severve = lblSeverity.Text;
                switch (lblSeverity.Text.Trim())
                {
                    case "0": case "1": case "2": case "3":
                        severve += " - Low";
                        break;
                    case "4": case "5": case "6":
                        severve += " - Medium";
                        break;
                    case "7":
                    case "8":
                        severve += " - High";
                        break;
                    case "9": case "10":
                        severve += " - Very High";
                        break;
                }
                lblSeverity.Text = severve;

                if(lblPrivate.Text.ToLower() == "y")
                {
                    lblPrivate.Text = "Private";
                }
                else
                {
                    lblPrivate.Text = " Public";
                    lblPrivate.CssClass = "glyphicon glyphicon-flag";
                    e.Row.Cells[6].BackColor = System.Drawing.Color.Yellow;
                    lblPrivate.Style.Add("color", "red");
                }
            }
        }

        public static List<string> SplitChunkData(string logData)
        {
            string input = logData;
            List<string> nList = new List<string>(input.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries));
            
            return nList;

        }

        public static DataTable keyValue(List<string> batchesData)
        {
            DataTable outputDT = new DataTable();

            outputDT.Columns.Add("batchID", typeof(int));
            outputDT.Columns.Add("keys", typeof(string));
            outputDT.Columns.Add("value", typeof(string));

            List<string> parseData = new List<string>();

            parseData.Add("src");
            parseData.Add("rt");
            parseData.Add("act");
            parseData.Add("cn3");
            parseData.Add("request");
            
            int uID = 1;

            foreach (string logData in batchesData)
            {
                

                string severity = "";

                int indexSeverity = logData.LastIndexOf('|');

                string seperator = logData.Substring(0, indexSeverity);

                severity = seperator.Substring(seperator.LastIndexOf('|') + 1);

                DataRow r = outputDT.NewRow();
                r["batchID"] = uID;
                r["keys"] = "severity";
                r["value"] = severity;

                outputDT.Rows.Add(r);

                int s = logData.IndexOf("app=");

                string startLog = logData.Substring(s);

                string pattern = "(?<=^[^=]+=)[^=]+[\\s]";

                foreach (string k in parseData)
                {
                    string searchPattern = @"\b" + k + @"\b";

                    bool result = Regex.IsMatch(startLog, searchPattern);

                    if (result)
                    {

                        DateTime timeStampt = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

                        int indexOfKey = startLog.IndexOf(k);

                        string key = k;

                        string cutoff = startLog.Substring(indexOfKey);

                        string value = Regex.Match(cutoff, pattern).ToString();

                        DataRow dr = outputDT.NewRow();
                        dr["batchID"] = uID;
                        dr["keys"] = key;
                        dr["value"] = value;
                        outputDT.Rows.Add(dr);
                    }
                }
                uID++;
            }
            return outputDT;
        }
        public static bool checkPrivateIP(string ip)
        {
            bool result = true;

            if(ip.Trim().Length > 0)
            {
                string Cip = (Convert.ToInt16(ip.Replace(",", ".").Split('.')[0])).ToString();
                Cip += "." + (Convert.ToInt16(ip.Replace(",", ".").Split('.')[1])).ToString();
                Cip += "." + (Convert.ToInt16(ip.Replace(",", ".").Split('.')[2])).ToString();
                Cip += "." + (Convert.ToInt16(ip.Replace(",", ".").Split('.')[3])).ToString();

                IPAddress nIP;

                if(IPAddress.TryParse(Cip,out nIP))
                {
                    byte[] tIp = nIP.GetAddressBytes();
                    switch (tIp[0])
                    {
                        case 10:
                        case 127:
                            return result;
                        case 172:
                            result = (tIp[1] > 16 && tIp[1] < 32);
                            return result;
                        case 192:
                            result = tIp[1] == 168;
                            return result;
                        default:
                            result = false;
                            return result;
                    }
                }
                else
                {
                    result = false;
                }
               
            }
            return result;
        }

        protected void btnClear_Click(object sender, EventArgs e)
        {
            txtData.Text = "";
            gvData.DataSource = null;
            gvData.DataBind();
        }
    }
    
}