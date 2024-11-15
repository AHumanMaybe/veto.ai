import { useState, useEffect, useRef } from 'react';
import './App.css';

function App() {
  const [anomalies, setAnomalies] = useState([]);
  const [isRunning, setIsRunning] = useState(false);
  const [iscompliant, setIsCompliant] = useState("")

  const intervalRef = useRef(null);  // To store the interval ID

  // Function to fetch anomalies from the backend
  const fetchAnomalies = async () => {
    try {
      const response = await fetch('http://localhost:5000/start_detection_sse');
      const data = await response.json();
      console.log(data); // Log the response
  
      // Check if the data has the "action" key instead of an array
      if (data.action) {
        const currentTime = new Date().toLocaleString(); // Get the current time in a human-readable format
        setAnomalies(prevAnomalies => [
          ...prevAnomalies,
          { action: data.action, time: currentTime }
        ]); // Add the action and time as a new anomaly
      } else {
        console.error("Fetched data does not contain an 'action' key:", data);
      }
    } catch (error) {
      console.error("Error fetching anomalies:", error);
    }
  };

  const fetchCompliance = async () => {
    try {
      const response = await fetch('http://localhost:5000/check_registry_value?key=HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments&value=ScanWithAntiVirus')
      const data = await response.json()

      if (data.result) {
        setIsCompliant(data.result)
      }
      else {
        console.error("Fetched data does not contain a check key:", data)
      }
    } catch (error) {
      console.error("Error fetching compliance", error)
    }
  }

  // Function to start/stop the repeated fetch call
  const toggleDetection = () => {
    if (isRunning) {
      clearInterval(intervalRef.current);  // Stop the interval if already running
      setIsRunning(false);
    } else {
      intervalRef.current = setInterval(() => {
        fetchAnomalies();  // Call the fetch function every 5 seconds
      }, 5000); // 5 seconds interval
      setIsRunning(true);
    }
  };

  // Clean up on component unmount to avoid memory leaks
  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);  // Clear interval when the component unmounts
      }
    };
  }, []);

  // Function to export anomalies to a CSV file
  const exportToCSV = () => {
    // Convert anomalies data to CSV format
    const headers = ["Action", "Time"];
    const rows = anomalies.map(anomaly => [anomaly.action, anomaly.time]);

    let csvContent = "data:text/csv;charset=utf-8,";
    csvContent += headers.join(",") + "\r\n";  // Add headers to the CSV content
    rows.forEach(row => {
      csvContent += row.join(",") + "\r\n";  // Add each row to the CSV content
    });

    // Create a download link for the CSV file
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", "anomalies_log.csv");
    document.body.appendChild(link);
    link.click();  // Trigger the download
    document.body.removeChild(link);  // Remove the link after downloading
  };

  return (
    <div className="flex-col w-full">
      <div className="flex justify-center items-center w-full my-2">
        <img src="/vetoai.png" className="h-16 w-auto" alt="Veto.AI Logo" />
      </div>
      
      <h1 className="text-5xl font-bold mb-4"><span className='text-red-500'>Veto.AI</span> Anomaly Response Log</h1>

      <div className='space-x-2'>
          {/* Button to start/stop anomaly detection */}
        <button
          onClick={toggleDetection}
          className="mb-4 px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600"
        >
          {isRunning ? 'Stop Detection' : 'Start Detection'}
        </button>

        {/* Button to export the anomalies to CSV */}
        <button
          onClick={exportToCSV}
          className="mb-4 px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
        >
          Export to CSV
        </button>
      </div>
      

      {/* Scrollable container */}
      <div className="flex w-full h-64 border-2 border-stone-600 rounded overflow-y-scroll p-2 justify-center">
        <ul className="flex-col w-5/6 rounded-lg list-none space-y-2">
          {anomalies.length > 0 ? (
            anomalies.map((anomaly, index) => (
              <li key={index} className="text-white border-b border-stone-600 hover:bg-stone-700 cursor-pointer">
                <strong>Action:</strong> {anomaly.action} 
                <br />
                <small className="text-gray-400">Detected at: {anomaly.time}</small>
              </li>
            ))
          ) : (
            <p>No anomalies detected.</p>
          )}
        </ul>
      </div>
      <button onClick={fetchCompliance} className="mb-4 px-4 py-2 bg-orange-500 text-white rounded hover:bg-orange-600">
          Check Compliance
      </button>
      <span 
        className={`flex justify-center ${iscompliant.includes('keep') ? 'text-green-500' : 'text-red-500'}`}
      >
        {iscompliant}
      </span>
    </div>
  );
}

export default App;
