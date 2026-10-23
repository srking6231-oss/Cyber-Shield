#include <bits/stdc++.h>
using namespace std;

struct user
{
    int    event_id;
    string ip_address;
    string event_type;
    int    severity;

    user *next = nullptr;
    user *back = nullptr;
};

int main()
{
    vector<user> v1;
    queue<user> alertQueue;     // FIFO  — for options 9 & 10
    stack<user> historyStack;   // LIFO  — for options 11 & 12
    int a = 0;

    while (a != 14)
    {
        cout << "============= CyberShield =============\n"
             << "1. Add security event.\n"
             << "2. Display all events.\n"
             << "3. Search event.\n"
             << "4. Sort by severity.\n"
             << "5. Sort by event ID.\n"
             << "6. Display singly linked list.\n"
             << "7. Display doubly linked list.\n"
             << "8. Review circular linked list.\n"
             << "9. Add an event to alert queue.\n"
             << "10. Process the next alert.\n"
             << "11. Push an event onto the history stack.\n"
             << "12. Pop the history stack.\n"
             << "13. Detect suspicious IP addresses.\n"
             << "14. Exit.\n"
             << "Choose option: ";
        cin >> a;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (a)
        {
        case 1:
        {
            int n;
            cout << "Enter how many event you want to add: ";
            cin >> n;
            user u;
            cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
            for(int i=0; i<n; i++)
            {
                cin >> u.event_id >> u.ip_address >> u.event_type >> u.severity;
                v1.push_back(u);
            }
            break;
        }
        case 2:
            if (v1.empty())
            {
                cout << "No events stored yet.\n";
            }
            else
            {
                cout << "============= SECURITY EVENTS =============\n";
                cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
                cout << "-------------------------------------------\n";
                for (size_t i = 0; i < v1.size(); i++)
                {
                    cout << v1[i].event_id   << " | "
                         << v1[i].ip_address << " | "
                         << v1[i].event_type << " | "
                         << v1[i].severity   << "\n";
                }
            }
            break;

        case 3:
        {
            //insertion sort;
            for(int i=1; i<v1.size(); i++)
            {
                int j = i;
                while(j>0 && v1[j-1].event_id>v1[j].event_id)
                {
                    swap(v1[j-1], v1[j]);
                    j--;
                }
            }

            int a;
            cout << "Which event you want to search, enter event_id: ";
            cin >> a;

            //binary search;
            int n = v1.size();
            int first = 0;
            int last = n-1;
            int mid;
            int index = -1;
            bool found = false;

            while(first <= last)
            {

                mid = (first + last) / 2;

                if( a == v1[mid].event_id )
                {
                    found = true;
                    index = mid;
                    break;
                }

                else if(a < v1[mid].event_id)
                {
                    last = mid -1;
                }
                else
                {
                    first = mid + 1;
                }

            }

            if(found)
            {
                cout << "============= SECURITY EVENTS =============\n";
                cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
                cout << "-------------------------------------------\n";
                cout << v1[index].event_id   << " | "
                     << v1[index].ip_address << " | "
                     << v1[index].event_type << " | "
                     << v1[index].severity   << "\n";
            }
            else
            {
                cout << "Event is not recorded..";

            }

            break;
        }

        case 4:
        {
            //selection sort;
            for(int i=0; i<v1.size(); i++)
            {
                int mini = i;
                for(int j=i+1; j<v1.size(); j++)
                {
                    if(v1[mini].severity > v1[j].severity)
                    {
                        mini = j;
                    }
                }
                swap(v1[i], v1[mini]);
            }

            cout << "============= SECURITY EVENTS =============\n";
            cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
            cout << "-------------------------------------------\n";
            for (size_t i = 0; i < v1.size(); i++)
            {
                cout << v1[i].event_id   << " | "
                     << v1[i].ip_address << " | "
                     << v1[i].event_type << " | "
                     << v1[i].severity   << "\n";
            }

            break;
        }

        case 5:
        {
            //bubble sort;
            int n=v1.size();
            for(int i=0; i<n-1; i++)
            {
                for(int j =0; j<n-i-1; j++)
                {
                    if(v1[j].event_id > v1[j+1].event_id)
                    {
                        swap(v1[j], v1[j+1]);
                    }
                }
            }

            cout << "============= SECURITY EVENTS =============\n";
            cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
            cout << "-------------------------------------------\n";
            for (size_t i = 0; i < v1.size(); i++)
            {
                cout << v1[i].event_id   << " | "
                     << v1[i].ip_address << " | "
                     << v1[i].event_type << " | "
                     << v1[i].severity   << "\n";
            }

            break;
        }

        case 6:
        {
            //singly linked list;
            user *head = nullptr;
            user *tail = nullptr;

            for(int i = 0; i < v1.size(); i++)
            {
                user *temp = new user;

                temp->event_id = v1[i].event_id;
                temp->ip_address = v1[i].ip_address;
                temp->event_type = v1[i].event_type;
                temp->severity = v1[i].severity;
                temp->next = nullptr;

                if(head == nullptr)
                {
                    head = temp;
                    tail = temp;
                }
                else
                {
                    tail->next = temp;
                    tail = temp;
                }
            }

            user *temp = head;

            cout << "============= SECURITY EVENTS =============\n";
            cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
            cout << "-------------------------------------------\n";

            while(temp != nullptr)
            {
                cout << temp->event_id << " | "
                     << temp->ip_address << " | "
                     << temp->event_type << " | "
                     << temp->severity << "\n";

                temp = temp->next;
            }

            tail->next = nullptr;
            for (user *t = head; t != nullptr; )
            {
                user *n = t->next;
                delete t;
                t = n;
            }

            break;
        }

        case 7:
        {
            //doubly linkedlist;
            user *head = nullptr;
            user *tail = nullptr;

            for(int i = 0; i < v1.size(); i++)
            {
                user *temp = new user;

                temp->event_id = v1[i].event_id;
                temp->ip_address = v1[i].ip_address;
                temp->event_type = v1[i].event_type;
                temp->severity = v1[i].severity;
                temp->next = nullptr;
                temp->back = nullptr;

                if(head == nullptr)
                {
                    head = temp;
                    tail = temp;
                }
                else
                {
                    tail->next = temp;
                    temp->back = tail;
                    tail = temp;
                }
            }

            user *temp = head;

            cout << "============= SECURITY EVENTS =============\n";
            cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
            cout << "-------------------------------------------\n";

            while(temp != nullptr)
            {
                cout << temp->event_id << " | "
                     << temp->ip_address << " | "
                     << temp->event_type << " | "
                     << temp->severity << "\n";

                temp = temp->next;
            }

            tail->next = nullptr;
            for (user *t = head; t != nullptr; )
            {
                user *n = t->next;
                delete t;
                t = n;
            }

            break;
        }

        case 8:
        {
            //circular linked list;
            user *head = nullptr;
            user *tail = nullptr;

            for (size_t i = 0; i < v1.size(); i++)
            {
                user *temp = new user;
                temp->event_id   = v1[i].event_id;
                temp->ip_address = v1[i].ip_address;
                temp->event_type = v1[i].event_type;
                temp->severity   = v1[i].severity;
                temp->next       = nullptr;

                if (head == nullptr)
                {
                    head = temp;
                    tail = temp;
                }
                else
                {
                    tail->next = temp;
                    tail = temp;
                }
            }

            // close the ring ONCE, after building the list
            if (tail != nullptr)
                tail->next = head;

            if (head == nullptr)
            {
                cout << "No events stored yet.\n";
                break;
            }

            cout << "============= SECURITY EVENTS =============\n";
            cout << "Event ID " << " | " << " IP " << " | " << " Event Type " << " | " << " Severity \n";
            cout << "-------------------------------------------\n";
            user *temp = head;
            do
            {
                cout << temp->event_id   << " | "
                     << temp->ip_address << " | "
                     << temp->event_type << " | "
                     << temp->severity   << "\n";
                temp = temp->next;
            }
            while (temp != head);

            // cleanup — break the ring first, then delete
            tail->next = nullptr;
            for (user *t = head; t != nullptr; )
            {
                user *n = t->next;
                delete t;
                t = n;
            }
            break;
        }

        case 9:
        {
            // Add an event to the alert queue (FIFO)
            int id;
            cout << "Enter event ID to queue for alerting: ";
            cin >> id;

            bool found = false;
            user picked;
            for (size_t i = 0; i < v1.size(); i++)
            {
                if (v1[i].event_id == id)
                {
                    picked = v1[i];
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                cout << "Event " << id << " not found.\n";
            }
            else
            {
                alertQueue.push(picked);
                cout << "Event " << id << " added to alert queue.\n";
                cout << "Queue size: " << alertQueue.size() << "\n";
            }
            break;
        }

        case 10:
        {
            // Process the next alert (removes from front of queue)
            if (alertQueue.empty())
            {
                cout << "No pending alerts.\n";
                break;
            }

            user alert = alertQueue.front();
            alertQueue.pop();

            cout << "=== Processing Alert ===\n";
            cout << "Event ID : " << alert.event_id   << "\n";
            cout << "IP       : " << alert.ip_address << "\n";
            cout << "Type     : " << alert.event_type << "\n";
            cout << "Severity : " << alert.severity   << "\n";
            cout << "Remaining in queue: " << alertQueue.size() << "\n";
            break;
        }

        case 11:
        {
            // Push an event onto the history stack (LIFO)
            int id;
            cout << "Enter event ID to push onto history stack: ";
            cin >> id;

            bool found = false;
            user picked;
            for (size_t i = 0; i < v1.size(); i++)
            {
                if (v1[i].event_id == id)
                {
                    picked = v1[i];
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                cout << "Event " << id << " not found.\n";
            }
            else
            {
                historyStack.push(picked);
                cout << "Event " << id << " pushed onto history stack.\n";
                cout << "Stack size: " << historyStack.size() << "\n";
            }
            break;
        }

        case 12:
        {
            // Pop the most recent history entry
            if (historyStack.empty())
            {
                cout << "History stack is empty.\n";
                break;
            }

            user h = historyStack.top();
            historyStack.pop();

            cout << "=== Popped from History ===\n";
            cout << "Event ID : " << h.event_id   << "\n";
            cout << "IP       : " << h.ip_address << "\n";
            cout << "Type     : " << h.event_type << "\n";
            cout << "Severity : " << h.severity   << "\n";
            cout << "Remaining in stack: " << historyStack.size() << "\n";
            break;
        }

        case 13:
        {
            // Detect suspicious IPs
            if (v1.empty())
            {
                cout << "No events to analyze.\n";
                break;
            }

            struct IPStat
            {
                string ip;
                int   total  = 0;   // every event for this IP
                int   failed = 0;   // only LoginFailed / BruteForce
            };

            vector<IPStat> stats;

            for (int i = 0; i < v1.size(); i++)
            {
                // Look for an existing entry for this IP
                int pos = -1;
                for (int j = 0; j < stats.size(); j++)
                {
                    if (stats[j].ip == v1[i].ip_address)
                    {
                        pos = (int)j;
                        break;
                    }
                }

                // Not found -> create a new entry
                if (pos == -1)
                {
                    IPStat s;
                    s.ip = v1[i].ip_address;
                    stats.push_back(s);
                    pos = (int)stats.size() - 1;
                }

                stats[pos].total++;
                if (v1[i].event_type == "LoginFailed" ||
                        v1[i].event_type == "BruteForce")
                {
                    stats[pos].failed++;
                }
            }

            cout << "=== IP Activity Report ===\n";
            for (int i = 0; i < stats.size(); i++)
                cout << stats[i].ip << " -> " << stats[i].total << " event(s)\n";

            cout << "\n=== Suspicious IPs (2+ failed attempts) ===\n";
            bool flagged = false;
            for (int i = 0; i < stats.size(); i++)
            {
                if (stats[i].failed >= 2)
                {
                    cout << "!! " << stats[i].ip
                         << " -> " << stats[i].failed << " failed attempts\n";
                    flagged = true;
                }
            }
            if (!flagged)
                cout << "No suspicious IPs detected.\n";

            break;
        }

        case 14:
            cout << "Goodbye..\n";
            break;

        default:
            cout << "Error\n";
        }
    }
    return 0;
}
